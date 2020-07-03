Xây dựng công cụ thu thập thông tin session sử dụng thư viện libpcap

**1. Cài đặt:**
  - Yêu cầu 
    + Thư viện libpcap và trình biên dịch ngôn ngữ C (gcc):     sudo apt-get install libpcap-dev gcc
  - Cài đăt:
    + git clone https://github.com/levanvi1998/giam_sat_mang.git
    + cd giam_sat_mang
    + gcc gsm.c -lpcap -o gsm
    + sudo ./gsm
  ![Screenshot from 2020-07-02 22-31-28](https://user-images.githubusercontent.com/36982693/86378426-da8c0a00-bcb3-11ea-80d7-fdef5ae2584f.png)
  
**2. Sử dụng:**
  - Nhập số thứ tự của card mạng cần thu thập thông tin.
  
  - Chương trình sẽ sinh ra 3 file: 
      + capture.pcap    dữ liệu thu thập được của card mạng đã chọn.
      + log.txt         thống kê thông tin các gói tin thu thập.
      + session.txt     thông kê gói tin TCP : SYN, SYN-ACK, ACK
      ![Screenshot from 2020-07-02 22-39-19](https://user-images.githubusercontent.com/36982693/86379363-f3e18600-bcb4-11ea-903f-a8469497873c.png)
      ![Screenshot from 2020-07-03 15-15-35](https://user-images.githubusercontent.com/36982693/86447864-25536380-bd40-11ea-9dfe-906b1cfa5738.png)
      ![Screenshot from 2020-07-02 22-46-12](https://user-images.githubusercontent.com/36982693/86380095-e7a9f880-bcb5-11ea-8351-31b2710b15c5.png)
