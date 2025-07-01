# app.py
import os
import hashlib
import json
from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for, session, flash
from werkzeug.utils import secure_filename, safe_join
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import logging
import time
import random

# --- CẤU HÌNH ---
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
CLOUD_STORAGE_FOLDER = 'cloud_storage'
HASH_CHUNK_SIZE = 65536

# Cấu hình Secret Key cho Session (RẤT QUAN TRỌNG CHO BẢO MẬT)
app.secret_key = os.urandom(24)

# Cấu hình logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Tạo các thư mục nếu chưa tồn tại
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CLOUD_STORAGE_FOLDER, exist_ok=True)

# Biến toàn cục để kiểm soát giả lập lỗi mạng
SIMULATE_NETWORK_ERROR = True

# --- QUẢN LÝ NGƯỜI DÙNG ---
USERS_DB_FILE = 'users.json'

def load_users():
    """Tải dữ liệu người dùng từ file JSON."""
    if os.path.exists(USERS_DB_FILE):
        try:
            with open(USERS_DB_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Lỗi đọc file {USERS_DB_FILE}. Khởi tạo người dùng mới.")
            return {'admin': generate_password_hash('1234')}
    default_users = {'admin': generate_password_hash('1234')}
    save_users(default_users)
    return default_users

def save_users(users_data):
    """Lưu dữ liệu người dùng vào file JSON."""
    try:
        with open(USERS_DB_FILE, 'w') as f:
            json.dump(users_data, f, indent=4)
    except Exception as e:
        logging.error(f"Lỗi khi lưu người dùng vào file {USERS_DB_FILE}: {str(e)}")

# Tải người dùng khi ứng dụng khởi động
USERS = load_users()

# --- CÁC HÀM HỖ TRỢ BẢO MẬT ---
def calculate_hash(file_path):
    """Tính toán giá trị hash SHA-256 cho một file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Lỗi khi tính hash cho {file_path}: {str(e)}")
        raise

def process_encryption(file_path, base_filename, download_password_for_file, uploader_username):
    """Mã hóa file, lưu file mã hóa, key, hash, mật khẩu download và tên người upload vào cloud_storage."""
    try:
        # 1. Tính hash của file gốc
        original_hash = calculate_hash(file_path)
        with open(os.path.join(CLOUD_STORAGE_FOLDER, base_filename + '.hash'), 'w') as f_hash:
            f_hash.write(original_hash)

        # 2. Tạo key AES và lưu lại
        key = get_random_bytes(16)
        with open(os.path.join(CLOUD_STORAGE_FOLDER, base_filename + '.key'), 'wb') as f_key:
            f_key.write(key)

        # 3. Mã hóa file
        cipher = AES.new(key, AES.MODE_EAX)
        with open(file_path, 'rb') as f_in:
            data_to_encrypt = f_in.read()
        
        ciphertext, tag = cipher.encrypt_and_digest(data_to_encrypt)

        # 4. Lưu file đã mã hóa
        encrypted_file_path = os.path.join(CLOUD_STORAGE_FOLDER, base_filename + '.enc')
        with open(encrypted_file_path, 'wb') as f_out:
            [f_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
        
        # 5. Băm và lưu mật khẩu download riêng cho file này
        hashed_download_password = hashlib.sha256(download_password_for_file.encode()).hexdigest()
        with open(os.path.join(CLOUD_STORAGE_FOLDER, base_filename + '.dpass'), 'w') as f_dpass:
            f_dpass.write(hashed_download_password)
        
        # 6. Lưu tên người upload
        with open(os.path.join(CLOUD_STORAGE_FOLDER, base_filename + '.owner'), 'w') as f_owner:
            f_owner.write(uploader_username)

        return True
    except Exception as e:
        logging.error(f"Lỗi khi mã hóa file {base_filename}: {str(e)}")
        raise

# --- CÁC ROUTE (API ENDPOINTS) CỦA WEB ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Xử lý đăng nhập người dùng."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in USERS and check_password_hash(USERS[username], password):
            session['logged_in'] = True
            session['username'] = username
            flash('Đăng nhập thành công!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Xử lý đăng ký tài khoản mới."""
    global USERS
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Vui lòng điền đủ tên đăng nhập và mật khẩu.', 'error')
            return render_template('register.html')

        if username in USERS:
            flash('Tên đăng nhập đã tồn tại. Vui lòng chọn tên khác.', 'error')
            return render_template('register.html', username=username)

        hashed_password = generate_password_hash(password)
        USERS[username] = hashed_password
        save_users(USERS)
        flash('Đăng ký tài khoản thành công! Vui lòng đăng nhập.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Đăng xuất người dùng."""
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('login'))

@app.before_request
def require_login():
    """Middleware để kiểm tra trạng thái đăng nhập cho tất cả các route ngoại trừ login, register và static."""
    if request.endpoint not in ['login', 'static', 'logout', 'register', 'get_username'] and not session.get('logged_in'):
        flash('Vui lòng đăng nhập để truy cập trang này.', 'info')
        return redirect(url_for('login'))

@app.route('/get_username', methods=['GET'])
def get_username():
    """Trả về tên người dùng hiện tại nếu đã đăng nhập."""
    return jsonify({'username': session.get('username')})

@app.route('/')
def index():
    """Trang chủ, hiển thị giao diện upload/download."""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Xử lý việc upload và mã hóa file."""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Vui lòng đăng nhập để upload file.'}), 401
    
    uploader_username = session['username']

    if 'video' not in request.files:
        return jsonify({'status': 'error', 'message': 'Không có file nào được chọn'}), 400
    
    file = request.files['video']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'Chưa chọn file'}), 400

    download_password_for_file = request.form.get('download_password_upload')
    if not download_password_for_file:
        return jsonify({'status': 'error', 'message': 'Vui lòng đặt mật khẩu tải về cho file.'}), 400

    try:
        safe_filename = secure_filename(file.filename)
        if not safe_filename:
            return jsonify({'status': 'error', 'message': 'Tên file không hợp lệ'}), 400
        
        temp_path = os.path.join(UPLOAD_FOLDER, safe_filename)
        file.save(temp_path)
        
        if SIMULATE_NETWORK_ERROR and random.random() < 0.5:
            os.remove(temp_path)
            return jsonify({'status': 'error', 'message': 'Giả lập lỗi mạng! Upload không thành công. Vui lòng thử lại.'}), 503

        process_encryption(temp_path, safe_filename, download_password_for_file, uploader_username)

        os.remove(temp_path)
        
        return jsonify({
            'status': 'success',
            'message': f'File "{safe_filename}" đã được upload và mã hóa thành công bởi {uploader_username}!'
        })
    except Exception as e:
        logging.error(f"Lỗi khi upload file {file.filename}: {str(e)}")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'status': 'error', 'message': f'Lỗi khi xử lý upload: {str(e)}'}), 500

@app.route('/files', methods=['GET'])
def list_files():
    """Lấy danh sách các file có trong 'Cloud' kèm thông tin người upload."""
    try:
        file_data = []
        for f_name in os.listdir(CLOUD_STORAGE_FOLDER):
            if f_name.endswith('.enc'):
                base_filename = f_name.replace('.enc', '')
                
                uploader = "Không rõ"
                owner_path = safe_join(CLOUD_STORAGE_FOLDER, base_filename + '.owner')
                if os.path.exists(owner_path):
                    try:
                        with open(owner_path, 'r') as f_owner:
                            uploader = f_owner.read().strip()
                    except Exception as e:
                        logging.error(f"Lỗi khi đọc file .owner cho {base_filename}: {str(e)}")

                file_data.append({'filename': base_filename, 'uploader': uploader})
        return jsonify(file_data)
    except Exception as e:
        logging.error(f"Lỗi khi liệt kê file: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Lỗi khi lấy danh sách file'}), 500

@app.route('/download', methods=['POST'])
def download_file():
    """Xử lý việc download, giải mã và xác thực file, yêu cầu mật khẩu riêng của file."""
    filename = request.form.get('filename')
    download_password_input = request.form.get('download_password')

    if not filename or not download_password_input:
        return jsonify({'status': 'error', 'message': 'Thiếu tên file hoặc mật khẩu tải xuống.'}), 400

    try:
        safe_filename = secure_filename(filename)
        if not safe_filename:
            return jsonify({'status': 'error', 'message': 'Tên file không hợp lệ!'}), 400
        
        encrypted_path = safe_join(CLOUD_STORAGE_FOLDER, safe_filename + '.enc')
        key_path = safe_join(CLOUD_STORAGE_FOLDER, safe_filename + '.key')
        hash_path = safe_join(CLOUD_STORAGE_FOLDER, safe_filename + '.hash')
        dpass_path = safe_join(CLOUD_STORAGE_FOLDER, safe_filename + '.dpass')
    except Exception as e:
        logging.error(f"Lỗi khi xử lý tên file {filename}: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Tên file không hợp lệ!'}), 400

    if not all(os.path.exists(p) for p in [encrypted_path, key_path, hash_path, dpass_path]):
        logging.error(f"Một hoặc nhiều thành phần của file không tồn tại: {safe_filename}")
        return jsonify({'status': 'error', 'message': 'File hoặc các thành phần bảo mật không tồn tại.'}), 404

    try:
        with open(dpass_path, 'r') as f:
            stored_hashed_download_password = f.read()

        input_hashed_password = hashlib.sha256(download_password_input.encode()).hexdigest()

        if input_hashed_password != stored_hashed_download_password:
            return jsonify({'status': 'error', 'message': 'Mật khẩu tải xuống không chính xác.'}), 401

        with open(key_path, 'rb') as f:
            key = f.read()
        with open(hash_path, 'r') as f:
            original_hash = f.read()
    except Exception as e:
        logging.error(f"Lỗi khi đọc key, hash hoặc mật khẩu download cho {safe_filename}: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Lỗi khi đọc thành phần bảo mật: {str(e)}'}), 500

    try:
        with open(encrypted_path, 'rb') as f_in:
            nonce, tag, ciphertext = [f_in.read(x) for x in (16, 16, -1)]
        
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        logging.error(f"Lỗi giải mã file {safe_filename}: File bị thay đổi hoặc khóa không đúng")
        return jsonify({'status': 'error', 'message': 'Lỗi giải mã: File trên cloud đã bị thay đổi hoặc khóa không đúng!'}), 500
    except Exception as e:
        logging.error(f"Lỗi khi giải mã file {safe_filename}: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Lỗi khi giải mã: {str(e)}'}), 500

    temp_decrypted_path = safe_join(UPLOAD_FOLDER, 'decrypted_' + safe_filename)
    try:
        with open(temp_decrypted_path, 'wb') as f_out:
            f_out.write(decrypted_data)
    except Exception as e:
        logging.error(f"Lỗi khi lưu file giải mã {safe_filename}: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Lỗi khi lưu file giải mã: {str(e)}'}), 500

    try:
        downloaded_hash = calculate_hash(temp_decrypted_path)
        if downloaded_hash != original_hash:
            logging.error(f"File {safe_filename} không toàn vẹn: Hash không khớp")
            os.remove(temp_decrypted_path)
            return jsonify({'status': 'error', 'message': 'Dữ liệu không toàn vẹn! File đã bị lỗi trong quá trình xử lý.'}), 500
    except Exception as e:
        logging.error(f"Lỗi khi kiểm tra hash cho {safe_filename}: {str(e)}")
        os.remove(temp_decrypted_path)
        return jsonify({'status': 'error', 'message': f'Lỗi khi kiểm tra toàn vẹn: {str(e)}'}), 500

    try:
        response = send_from_directory(UPLOAD_FOLDER, 'decrypted_' + safe_filename, as_attachment=True, download_name=safe_filename)
        return response
    except Exception as e:
        logging.error(f"Lỗi khi gửi file {safe_filename}: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Lỗi khi gửi file: {str(e)}'}), 500
    finally:
        max_attempts = 5
        attempt = 0
        while os.path.exists(temp_decrypted_path) and attempt < max_attempts:
            try:
                os.remove(temp_decrypted_path)
                logging.info(f"Đã xóa file tạm {temp_decrypted_path}")
                break
            except PermissionError:
                attempt += 1
                if attempt == max_attempts:
                    logging.error(f"Không thể xóa file tạm {temp_decrypted_path} sau {max_attempts} lần thử")
                else:
                    time.sleep(0.5)

@app.route('/toggle_network_error', methods=['POST'])
def toggle_network_error_status():
    global SIMULATE_NETWORK_ERROR
    SIMULATE_NETWORK_ERROR = not SIMULATE_NETWORK_ERROR
    status_text = "BẬT" if SIMULATE_NETWORK_ERROR else "TẮT"
    flash(f"Giả lập lỗi mạng đã được {status_text}.", 'info')
    return jsonify({'status': 'success', 'message': f'Giả lập lỗi mạng: {status_text}', 'enabled': SIMULATE_NETWORK_ERROR})

@app.route('/get_network_error_status', methods=['GET'])
def get_network_error_status():
    status_text = "BẬT" if SIMULATE_NETWORK_ERROR else "TẮT"
    return jsonify({'enabled': SIMULATE_NETWORK_ERROR, 'status_text': status_text})

@app.route('/delete_file', methods=['POST'])
def delete_file():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Yêu cầu đăng nhập để xóa file.'}), 401

    filename = request.form.get('filename')
    login_password_confirmation = request.form.get('login_password_confirmation') # Lấy mật khẩu đăng nhập từ frontend

    if not filename or not login_password_confirmation:
        return jsonify({'status': 'error', 'message': 'Thiếu tên file hoặc mật khẩu xác nhận.'}), 400

    safe_filename = secure_filename(filename)
    if not safe_filename:
        return jsonify({'status': 'error', 'message': 'Tên file không hợp lệ!'}), 400

    # 1. Xác minh người upload
    owner_path = safe_join(CLOUD_STORAGE_FOLDER, safe_filename + '.owner')
    if not os.path.exists(owner_path):
        return jsonify({'status': 'error', 'message': 'Không tìm thấy thông tin người upload cho file này.'}), 404

    try:
        with open(owner_path, 'r') as f_owner:
            file_uploader = f_owner.read().strip()
    except Exception as e:
        logging.error(f"Lỗi khi đọc file .owner cho {safe_filename}: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Lỗi khi kiểm tra quyền sở hữu file.'}), 500

    current_user = session.get('username')
    
    if current_user != file_uploader:
        return jsonify({'status': 'error', 'message': 'Bạn không có quyền xóa file này. Chỉ người upload mới có thể xóa.'}), 403

    # 2. Xác minh mật khẩu đăng nhập để xác nhận
    if current_user not in USERS:
        logging.error(f"Người dùng '{current_user}' không tồn tại trong DB khi cố gắng xóa file.")
        return jsonify({'status': 'error', 'message': 'Lỗi hệ thống: Không tìm thấy thông tin tài khoản người dùng.'}), 500

    if not check_password_hash(USERS[current_user], login_password_confirmation):
        return jsonify({'status': 'error', 'message': 'Mật khẩu đăng nhập không chính xác để xác nhận xóa.'}), 401

    # Nếu cả hai kiểm tra đều thành công, tiến hành xóa file
    file_extensions = ['.enc', '.key', '.hash', '.dpass', '.owner'] 
    deleted_count = 0
    total_expected = len(file_extensions)
    
    deleted_paths = [] 
    not_found_paths = []

    for ext in file_extensions:
        file_path = safe_join(CLOUD_STORAGE_FOLDER, safe_filename + ext)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                deleted_count += 1
                deleted_paths.append(file_path)
                logging.info(f"Đã xóa file: {file_path}")
            except Exception as e:
                logging.error(f"Lỗi khi xóa file {file_path}: {str(e)}")
                return jsonify({'status': 'error', 'message': f'Lỗi khi xóa một phần của file "{safe_filename}": {str(e)}'}), 500
        else:
            not_found_paths.append(file_path)
            logging.warning(f"File {file_path} không tồn tại khi cố gắng xóa.")

    if deleted_count == total_expected:
        return jsonify({'status': 'success', 'message': f'File "{safe_filename}" và tất cả các thành phần liên quan đã bị xóa hoàn toàn.'})
    elif deleted_count > 0:
        return jsonify({'status': 'warning', 'message': f'File "{safe_filename}" đã xóa {deleted_count}/{total_expected} thành phần. Một số thành phần không tìm thấy ({len(not_found_paths)}): {", ".join(not_found_paths)} hoặc không thể xóa.'}), 200
    else:
        return jsonify({'status': 'error', 'message': f'Không tìm thấy file "{safe_filename}" nào để xóa.'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5001)