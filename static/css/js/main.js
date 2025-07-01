// static/js/main.js
document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('upload-form');
    const videoInput = document.getElementById('video-input');
    const uploadStatus = document.getElementById('upload-status');
    const progressBar = document.getElementById('upload-progress');
    const fileListContainer = document.getElementById('file-list-container');
    const refreshBtn = document.getElementById('refresh-btn');

    // --- XỬ LÝ UPLOAD ---
    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        if (!videoInput.files.length) {
            showStatus('Vui lòng chọn một file video.', 'error');
            return;
        }

        const formData = new FormData();
        formData.append('video', videoInput.files[0]);

        progressBar.style.display = 'block';
        progressBar.value = 0;
        showStatus('Đang upload...', 'info');

        // Sử dụng XMLHttpRequest để có thể theo dõi tiến trình upload
        const xhr = new XMLHttpRequest();

        // Theo dõi tiến trình
        xhr.upload.addEventListener('progress', (event) => {
            if (event.lengthComputable) {
                const percentComplete = (event.loaded / event.total) * 100;
                progressBar.value = percentComplete;
            }
        });

        // Xử lý khi upload hoàn tất
        xhr.onload = () => {
            progressBar.style.display = 'none';
            const response = JSON.parse(xhr.responseText);

            if (xhr.status >= 200 && xhr.status < 300) {
                showStatus(response.message, 'success');
                loadFiles(); // Tải lại danh sách file
                uploadForm.reset();
            } else {
                showStatus(response.message || 'Có lỗi xảy ra.', 'error');
            }
        };
        
        // Xử lý lỗi mạng thực sự (khác với lỗi giả lập từ server)
        xhr.onerror = () => {
             progressBar.style.display = 'none';
             showStatus('Lỗi mạng không thể kết nối tới server.', 'error');
        };

        xhr.open('POST', '/upload');
        xhr.send(formData);
    });

    // --- HIỂN THỊ DANH SÁCH FILE ---
    const loadFiles = async () => {
        try {
            const response = await fetch('/files');
            const files = await response.json();

            fileListContainer.innerHTML = ''; // Xóa nội dung cũ

            if (files.length === 0) {
                fileListContainer.innerHTML = '<p>Chưa có file nào trên "Cloud".</p>';
                return;
            }
            
            const ul = document.createElement('ul');
            files.forEach(file => {
                const li = document.createElement('li');
                li.textContent = file;

                const downloadBtn = document.createElement('button');
                downloadBtn.textContent = 'Download & Giải Mã';
                downloadBtn.onclick = () => {
                    // Chuyển hướng trình duyệt đến URL download
                    window.location.href = `/download/${file}`;
                };

                li.appendChild(downloadBtn);
                ul.appendChild(li);
            });
            fileListContainer.appendChild(ul);

        } catch (error) {
            fileListContainer.innerHTML = '<p>Lỗi khi tải danh sách file.</p>';
            console.error('Error loading files:', error);
        }
    };

    function showStatus(message, type) {
        uploadStatus.textContent = message;
        uploadStatus.className = type; // 'success' hoặc 'error'
    }

    // Gắn sự kiện cho nút làm mới
    refreshBtn.addEventListener('click', loadFiles);

    // Tải danh sách file lần đầu khi trang được mở
    loadFiles();
});