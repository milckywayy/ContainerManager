import logging
import random
import string
from flask_cors import CORS
from flask import Flask, request, jsonify, abort
import docker
from docker import errors
import threading
import time
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
from functools import wraps
import psutil

app = Flask(__name__)
CORS(app)
client = docker.from_env()

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "200 per hour", "20 per minute"]
)

PASSWORD_LENGTH = 14
DEFAULT_STUDENT_PASSWORD = '12345678'

AVAILABLE_PORTS = [port for port in range(10000, 10501)]
OCCUPIED_PORTS = {}
SESSION_PASSWORDS = {}
CONTAINER_EXPIRATION_TIMES = {}

lock = threading.Lock()

EXPIRATION_INTERVAL = 30  # 30 minutes
CHECK_INTERVAL = 60  # Check every 60 seconds for expired vms
CONTAINER_TIME_EXTENSION = 15  # minutes
CONTAINER_MIN_TIME_TO_ALLOW_EXTENSION = 15  # minutes
MEMORY_THRESHOLD = 300  # Minimum MB of RAM available to create a new container

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TAG_TO_EXPOSED_PORT = {
    'vm': 22,
    'ws': 80,
    'sws': 443
}

with open('credentials/secret_key.json') as f:
    secret_data = json.load(f)
    SECRET_KEY = secret_data['secret']


def require_secret_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-Secret-Key') != SECRET_KEY:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def get_container_name(session_id):
    return f'CTF-{session_id}'


def generate_random_password(length=PASSWORD_LENGTH):
    characters = string.ascii_letters + string.digits
    random_password = ''.join(random.choice(characters) for _ in range(length))
    return random_password


def image_exists(image_name):
    try:
        client.images.get(image_name)
        return True
    except errors.ImageNotFound:
        return False


def is_container_created(container_name):
    try:
        client.containers.get(container_name)
        return True
    except docker.errors.NotFound:
        return False


def get_tag(image_name):
    return image_name.split(':')[1]


def check_memory_availability():
    memory_info = psutil.virtual_memory()
    available_memory_mb = memory_info.available / 1024 / 1024
    return available_memory_mb > MEMORY_THRESHOLD


def check_expired_containers():
    while True:
        with lock:
            now = datetime.now()
            expired_sessions = [session_id for session_id, expire_time in CONTAINER_EXPIRATION_TIMES.items() if now >= expire_time]

        for session_id in expired_sessions:
            logger.info(f"Container with session ID {session_id} has expired and will be removed.")
            _remove_container(session_id, get_container_name(session_id))

        time.sleep(CHECK_INTERVAL)


@app.route('/make_container/<image>', methods=['POST'])
@require_secret_key
def make_container(image):
    if not AVAILABLE_PORTS:
        logger.error("No available ports")
        return jsonify({'error': 'No available ports'}), 500

    if not image_exists(image):
        return jsonify({'error': 'Image not found'}), 404

    if not check_memory_availability():
        logger.error("Not enough memory to create a new container")
        return jsonify({'error': 'Resource limit reached. Please wait a moment and try again.'}), 500

    data = request.json
    session_id = data['session_id']
    name = get_container_name(session_id)

    if is_container_created(name):
        return jsonify({'error': 'Container already exists'}), 409

    tag = get_tag(image)
    with lock:
        port = random.choice(AVAILABLE_PORTS)
        exposed_port = TAG_TO_EXPOSED_PORT.get(tag)
        password = generate_random_password()
        AVAILABLE_PORTS.remove(port)
        OCCUPIED_PORTS[session_id] = port

    logger.info(f"Creating container with session ID {session_id} on port {port}")

    try:
        vm = client.containers.run(
            image,
            detach=True,
            ports={f'{exposed_port}/tcp': port},
            name=name
        )

        if tag == 'vm':
            SESSION_PASSWORDS[session_id] = password
            vm.exec_run(f"bash -c 'echo \"student:{password}\" | chpasswd'")

        with lock:
            CONTAINER_EXPIRATION_TIMES[session_id] = datetime.now() + timedelta(minutes=EXPIRATION_INTERVAL)

    except Exception as e:
        with lock:
            AVAILABLE_PORTS.append(port)
            del OCCUPIED_PORTS[session_id]

            if session_id in SESSION_PASSWORDS:
                del SESSION_PASSWORDS[session_id]

            if session_id in CONTAINER_EXPIRATION_TIMES:
                del CONTAINER_EXPIRATION_TIMES[session_id]

        logger.error(f"Error creating container: {e}")
        return jsonify({'error': str(e)}), 500

    logger.info(f"Container created: {name}")
    return jsonify(status='Container created'), 200


@app.route('/remove_container', methods=['DELETE'])
@require_secret_key
def remove_container():
    data = request.json
    session_id = data['session_id']

    container_name = get_container_name(session_id)

    if _remove_container(session_id, container_name):
        return jsonify(status='Container removed'), 200
    else:
        return jsonify({'error': 'Container could not be removed'}), 500


def _remove_container(session_id, container_name):
    try:
        container = client.containers.get(container_name)

        container.stop()
        container.remove()

        with lock:
            AVAILABLE_PORTS.append(OCCUPIED_PORTS[session_id])
            del OCCUPIED_PORTS[session_id]

            if session_id in SESSION_PASSWORDS:
                del SESSION_PASSWORDS[session_id]

            if session_id in CONTAINER_EXPIRATION_TIMES:
                del CONTAINER_EXPIRATION_TIMES[session_id]

        logger.info(f"Container removed: {container_name}")

    except Exception as e:
        logger.error(f"Error removing container: {e}")
        return False

    return True


@app.route('/container_status', methods=['POST'])
@require_secret_key
def container_status():
    if request.method != 'POST':
        return jsonify({'error': 'Method not allowed'}), 405

    data = request.json
    session_id = data['session_id']

    container_name = get_container_name(session_id)

    try:
        container = client.containers.get(container_name)

        tag = get_tag(container.image.tags[0])
        port = OCCUPIED_PORTS[session_id]

        access_command = None
        if tag == 'vm':
            access_command = f'ssh -p {port} student@<server_domain>'
        elif tag == 'ws':
            access_command = f'http://<server_domain>:{port}'
        elif tag == 'sws':
            access_command = f'https://<server_domain>:{port}'

        expiration_time = CONTAINER_EXPIRATION_TIMES.get(session_id, 'No expiration time found')
        if isinstance(expiration_time, datetime):
            expiration_time = expiration_time.strftime("%Y-%m-%d %H:%M:%S")
        vm_info = {
            'status': container.status,
            'port': OCCUPIED_PORTS.get(session_id),
            'password': SESSION_PASSWORDS.get(session_id),
            'expiration_time': expiration_time,
            'access_command': access_command
        }
        return jsonify(vm_info), 200

    except docker.errors.NotFound:
        return jsonify({'status': 'not_created'}), 200

    except Exception as e:
        logger.error(f"Error retrieving container status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/extend_container', methods=['POST'])
@require_secret_key
def extend_container():
    if request.method != 'POST':
        return jsonify({'error': 'Method not allowed'}), 405

    data = request.json
    session_id = data['session_id']

    with lock:
        if session_id not in CONTAINER_EXPIRATION_TIMES:
            return jsonify({'error': 'Container session not found'}), 404

        current_expiration = CONTAINER_EXPIRATION_TIMES[session_id]
        time_remaining = (current_expiration - datetime.now()).total_seconds() / 60

        if time_remaining < CONTAINER_MIN_TIME_TO_ALLOW_EXTENSION:
            CONTAINER_EXPIRATION_TIMES[session_id] = current_expiration + timedelta(minutes=CONTAINER_TIME_EXTENSION)
            logger.info(f"Extended expiration time for container with session ID {session_id} by {CONTAINER_TIME_EXTENSION} minutes.")
            return jsonify({'status': 'Container expiration extended'}), 200
        else:
            logger.info(f"Cannot extend container expiration for {session_id}: too much time remaining ({time_remaining} minutes).")
            return jsonify({'error': f'Cannot extend: more than {CONTAINER_MIN_TIME_TO_ALLOW_EXTENSION} minutes remaining'}), 403


@app.route('/restart_container', methods=['POST'])
@require_secret_key
def restart_container():
    if request.method != 'POST':
        return jsonify({'error': 'Method not allowed'}), 405

    data = request.json
    session_id = data['session_id']

    container_name = get_container_name(session_id)

    try:
        container = client.containers.get(container_name)
        container.restart()
        logger.info(f"Container restarted: {container_name}")
        return jsonify(status='Container restarted'), 200

    except docker.errors.NotFound:
        return jsonify({'error': 'Container not found'}), 404

    except Exception as e:
        logger.error(f"Error restarting container: {e}")
        return jsonify({'error': str(e)}), 500


threading.Thread(target=check_expired_containers, daemon=True).start()
