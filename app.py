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
import json
from functools import wraps
import psutil

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

app = Flask(__name__)
CORS(app)
client = docker.from_env()

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
    'vm': [22],
    'ws': [80],
    'sws': [443],
    'ws_over_vm': [80, 22]
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
    tag = get_tag(image)

    if tag not in TAG_TO_EXPOSED_PORT:
        logger.error(f"Tag {tag} not supported")

    ports_num = len(TAG_TO_EXPOSED_PORT[tag])

    if not AVAILABLE_PORTS or len(AVAILABLE_PORTS) < ports_num:
        logger.error("No available ports to create a new container.")
        return jsonify({'error': 'No available ports'}), 500

    if not image_exists(image):
        logger.error(f"Couldn't create new container. {image} does not exist.")
        return jsonify({'error': 'Image not found'}), 404

    if not check_memory_availability():
        logger.error("Not enough memory to create a new container")
        return jsonify({'error': 'Resource limit reached. Please wait a moment and try again.'}), 500

    data = request.json
    session_id = data['session_id']
    flag = data['flag']
    name = get_container_name(session_id)

    if is_container_created(name):
        return jsonify({'error': "Couldn't create new container. Container already exists"}), 409

    with (lock):
        ports = []
        for i in range(ports_num):
            port = random.choice(AVAILABLE_PORTS)
            ports.append(port)
            AVAILABLE_PORTS.remove(port)

        exposed_ports = TAG_TO_EXPOSED_PORT.get(tag)
        password = generate_random_password()

        OCCUPIED_PORTS[session_id] = ports

    try:
        vm = client.containers.run(
            image,
            detach=True,
            ports={f'{exposed_port}/tcp': host_port for exposed_port, host_port in zip(exposed_ports, ports)},
            name=name,
            environment={'FLAG': flag},
        )

        if tag == 'vm':
            SESSION_PASSWORDS[session_id] = password
            vm.exec_run(f"bash -c 'echo \"student:{password}\" | chpasswd'")
        else:
            SESSION_PASSWORDS[session_id] = "N/A"

        with lock:
            CONTAINER_EXPIRATION_TIMES[session_id] = datetime.now() + timedelta(minutes=EXPIRATION_INTERVAL)

    except Exception as e:
        with lock:
            for port in ports:
                AVAILABLE_PORTS.append(port)

            del OCCUPIED_PORTS[session_id]

            if session_id in SESSION_PASSWORDS:
                del SESSION_PASSWORDS[session_id]

            if session_id in CONTAINER_EXPIRATION_TIMES:
                del CONTAINER_EXPIRATION_TIMES[session_id]

        logger.error(f"Error while creating new container: {e}")
        return jsonify({'error': str(e)}), 500

    running_containers = len(client.containers.list())
    logger.info(f"Container created: {name} on ports {', '.join(str(port) for port in ports)}. Total running containers: {running_containers}.")
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
            for port in OCCUPIED_PORTS[session_id]:
                AVAILABLE_PORTS.append(port)

            del OCCUPIED_PORTS[session_id]

            if session_id in SESSION_PASSWORDS:
                del SESSION_PASSWORDS[session_id]

            if session_id in CONTAINER_EXPIRATION_TIMES:
                del CONTAINER_EXPIRATION_TIMES[session_id]

        running_containers = len(client.containers.list())
        logger.info(f"Container removed: {container_name}. Total running containers: {running_containers}.")

    except Exception as e:
        logger.error(f"Error removing container: {e}")
        return False

    return True


@app.route('/container_status/<image>', methods=['POST'])
@require_secret_key
def container_status(image):
    data = request.json
    session_id = data['session_id']

    container_name = get_container_name(session_id)

    if not is_container_created(container_name):
        return jsonify({'status': 'not_created'}), 200

    try:
        container = client.containers.get(container_name)
        container_image_name = container.image.tags[0]

        if container_image_name != image:
            logger.info(f'Removing old container for {session_id} because {container_image_name} does not match {image}')
            _remove_container(session_id, container_name)
            return jsonify({'status': 'not_created'}), 200

        tag = get_tag(container.image.tags[0])
        ports = OCCUPIED_PORTS[session_id]

        access_commands = None
        if tag == 'vm':
            access_commands = [f'ssh -p {ports[0]} student@<server_domain>']
        elif tag == 'ws':
            access_commands = [f'http://<server_domain>:{ports[0]}']
        elif tag == 'sws':
            access_commands = [f'https://<server_domain>:{ports[0]}']
        elif tag == 'ws_over_vm':
            access_commands = [f'http://<server_domain>:{ports[0]}', f'ssh -p {ports[1]} <server_domain>']

        expiration_time = CONTAINER_EXPIRATION_TIMES.get(session_id, 'No expiration time found')
        if isinstance(expiration_time, datetime):
            expiration_time = expiration_time.strftime("%Y-%m-%d %H:%M:%S")
        vm_info = {
            'status': container.status,
            'port': ', '.join(str(port) for port in ports),
            'password': SESSION_PASSWORDS.get(session_id),
            'expiration_time': expiration_time,
            'access_commands': access_commands
        }
        return jsonify(vm_info), 200

    except Exception as e:
        logger.error(f"Error retrieving container status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/extend_container', methods=['POST'])
@require_secret_key
def extend_container():
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
    data = request.json
    session_id = data['session_id']

    container_name = get_container_name(session_id)

    try:
        container = client.containers.get(container_name)
        container.restart()
        logger.info(f"Container restarted: {container_name}")
        return jsonify(status='Container restarted'), 200

    except docker.errors.NotFound:
        logger.info(f"Couldn't restart container. Container not found: {container_name}")
        return jsonify({'error': 'Container not found'}), 404

    except Exception as e:
        logger.error(f"Error restarting container: {e}")
        return jsonify({'error': str(e)}), 500


threading.Thread(target=check_expired_containers, daemon=True).start()

if __name__ == "__main__":
    app.run(host='localhost', debug=True)
