import logging
import random
import string
from queue import Queue
from flask_cors import CORS
from flask import Flask, request, jsonify
import docker
from docker import errors
import threading
import time
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)
client = docker.from_env()

PASSWORD_LENGTH = 14
DEFAULT_STUDENT_PASSWORD = '12345678'
AVAILABLE_PORTS = Queue()
for p in range(10000, 10501):  # 500 ports
    AVAILABLE_PORTS.put(p)
SESSION_PASSWORDS = {}
VM_EXPIRATION_TIMES = {}
EXPIRATION_INTERVAL = 30  # 30 minutes
CHECK_INTERVAL = 60  # Check every 60 seconds for expired vms
VM_TIME_EXTENSION = 15  # minutes
VM_MIN_TIME_TO_ALLOW_EXTENSION = 15  # minutes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_random_password(length=PASSWORD_LENGTH):
    characters = string.ascii_letters + string.digits
    random_password = ''.join(random.choice(characters) for _ in range(length))
    return random_password


def check_expired_vms():
    while True:
        now = datetime.now()
        expired_sessions = [session_id for session_id, expire_time in VM_EXPIRATION_TIMES.items() if now >= expire_time]

        for session_id in expired_sessions:
            logger.info(f"VM with session ID {session_id} has expired and will be removed.")
            _remove_vm(session_id, f'VM-{session_id}')

        time.sleep(CHECK_INTERVAL)


@app.route('/make_vm/<image>', methods=['POST'])
def make_vm(image):
    if request.method != 'POST':
        return jsonify({'error': 'Method not allowed'}), 405

    if not AVAILABLE_PORTS:
        logger.error("No available ports")
        return jsonify({'error': 'No available ports'}), 500

    data = request.json

    session_id = data['session_id']
    password = generate_random_password()
    port = AVAILABLE_PORTS.get()

    logger.info(f"Creating VM with session ID {session_id} on port {port}")

    try:
        vm = client.containers.run(
            image,
            detach=True,
            ports={'22/tcp': port},
            name=f'VM-{session_id}'
        )

        vm.exec_run(f"bash -c 'echo \"student:{password}\" | chpasswd'")

        SESSION_PASSWORDS[session_id] = password
        VM_EXPIRATION_TIMES[session_id] = datetime.now() + timedelta(minutes=EXPIRATION_INTERVAL)

    except Exception as e:
        AVAILABLE_PORTS.put(port)
        logger.error(f"Error creating container: {e}")
        return jsonify({'error': str(e)}), 500

    logger.info(f"Container created: VM-{session_id}")
    return jsonify(status='Container created', port=port, password=password), 200


@app.route('/remove_vm', methods=['DELETE'])
def remove_vm():
    if request.method != 'DELETE':
        return jsonify({'error': 'Method not allowed'}), 405

    data = request.json
    session_id = data['session_id']
    vm_name = f'VM-{session_id}'

    if _remove_vm(session_id, vm_name):
        return jsonify(status='Container removed'), 200
    else:
        return jsonify({'error': 'Container could not be removed'}), 500


def _remove_vm(session_id, vm_name):
    try:
        vm = client.containers.get(vm_name)
        port = vm.attrs['NetworkSettings']['Ports']['22/tcp'][0]['HostPort']
        vm.stop()
        vm.remove()
        AVAILABLE_PORTS.put(int(port))

        if session_id in SESSION_PASSWORDS:
            del SESSION_PASSWORDS[session_id]

        if session_id in VM_EXPIRATION_TIMES:
            del VM_EXPIRATION_TIMES[session_id]

        logger.info(f"Container removed: {vm_name}")

    except Exception as e:
        logger.error(f"Error removing container: {e}")
        return False

    return True


@app.route('/vm_status', methods=['POST'])
def vm_status():
    if request.method != 'POST':
        return jsonify({'error': 'Method not allowed'}), 405

    data = request.json

    session_id = data['session_id']
    vm_name = f'VM-{session_id}'

    try:
        vm = client.containers.get(vm_name)
        expiration_time = VM_EXPIRATION_TIMES.get(session_id, 'No expiration time found')
        if isinstance(expiration_time, datetime):
            expiration_time = expiration_time.strftime("%Y-%m-%d %H:%M:%S")
        vm_info = {
            'status': vm.status,
            'port': vm.attrs['NetworkSettings']['Ports']['22/tcp'][0]['HostPort'],
            'password': SESSION_PASSWORDS.get(session_id, 'Password not found'),
            'expiration_time': expiration_time
        }
        return jsonify(vm_info), 200

    except docker.errors.NotFound:
        return jsonify({'status': 'not_created'}), 200

    except Exception as e:
        logger.error(f"Error retrieving container status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/extend_vm', methods=['POST'])
def extend_vm():
    if request.method != 'POST':
        return jsonify({'error': 'Method not allowed'}), 405

    data = request.json

    session_id = data['session_id']

    if session_id not in VM_EXPIRATION_TIMES:
        return jsonify({'error': 'VM session not found'}), 404

    current_expiration = VM_EXPIRATION_TIMES[session_id]
    time_remaining = (current_expiration - datetime.now()).total_seconds() / 60

    if time_remaining < VM_MIN_TIME_TO_ALLOW_EXTENSION:
        VM_EXPIRATION_TIMES[session_id] = current_expiration + timedelta(minutes=VM_TIME_EXTENSION)
        logger.info(f"Extended expiration time for VM with session ID {session_id} by {VM_TIME_EXTENSION} minutes.")
        return jsonify({'status': 'VM expiration extended'}), 200
    else:
        logger.info(
            f"Cannot extend VM expiration for {session_id}: too much time remaining ({time_remaining} minutes).")
        return jsonify({'error': f'Cannot extend: more than {VM_MIN_TIME_TO_ALLOW_EXTENSION} minutes remaining'}), 403


@app.route('/restart_vm', methods=['POST'])
def restart_vm():
    if request.method != 'POST':
        return jsonify({'error': 'Method not allowed'}), 405

    data = request.json
    session_id = data['session_id']
    vm_name = f'VM-{session_id}'

    try:
        vm = client.containers.get(vm_name)
        vm.restart()
        logger.info(f"Container restarted: {vm_name}")
        return jsonify(status='Container restarted'), 200

    except docker.errors.NotFound:
        return jsonify({'error': 'VM not found'}), 404

    except Exception as e:
        logger.error(f"Error restarting container: {e}")
        return jsonify({'error': str(e)}), 500


threading.Thread(target=check_expired_vms, daemon=True).start()
if __name__ == '__main__':
    app.run()
