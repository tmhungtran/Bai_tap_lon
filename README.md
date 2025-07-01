# Bai_tap_lon
-- thứ tự thư mục 
/CloudVideoSimulator
|
|-- app.py                  # File Flask chính (backend)
|
|-- templates/
|   |-- index.html          # File giao diện người dùng (frontend)
|
|-- static/
|   |-- css/
|   |   |-- style.css       # File định dạng, làm đẹp trang web
|   |-- js/
|       |-- main.js         # File JavaScript xử lý logic phía client
|
|-- cloud_storage/          # Thư mục giả lập "Cloud" để lưu file đã mã hóa
|-- uploads/       
- chức năng của hệ thống:
  + quản lý người dùng.
  + quản lý tệp tin.
  + hỗ trợ và kiểm thử.
    Hệ thống được thiết kế là một ứng dụng web đơn giản nhưng hiệu quả, xây dựng bằng Flask,
    nhằm cung cấp một giải pháp cơ bản cho việc lưu trữ và quản lý tệp tin một cách an toàn.
    Ứng dụng tích hợp các tính năng cốt lõi như đăng ký, đăng nhập người dùng, cho phép họ tải lên các tệp tin,
    sau đó mã hóa dữ liệu bằng thuật toán AES mạnh mẽ và tính toán giá trị băm để đảm bảo tính toàn vẹn.
    Khi cần, người dùng có thể giải mã và tải xuống tệp của mình,
    với lớp bảo mật tăng cường là mật khẩu riêng cho từng tệp và kiểm soát quyền xóa dựa trên người sở hữu.
    Ngoài ra, hệ thống còn có khả năng giả lập lỗi mạng, hỗ trợ hiệu quả cho quá trình kiểm thử và phát triển.
