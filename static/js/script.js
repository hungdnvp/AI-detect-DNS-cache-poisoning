function showTab(tabName) {
  document.getElementById("realtime").classList.remove("active");
  document.getElementById("pcap").classList.remove("active");
  document.getElementById("realtime-tab-btn").classList.remove("active");
  document.getElementById("pcap-tab-btn").classList.remove("active");

  document.getElementById("realtime-tab-btn").classList.add("inactive");
  document.getElementById("pcap-tab-btn").classList.add("inactive");

  if (tabName === "realtime") {
    document.getElementById("realtime").classList.add("active");
    document.getElementById("realtime-tab-btn").classList.add("active");
    document.getElementById("realtime-tab-btn").classList.remove("inactive");
  } else if (tabName === "pcap") {
    document.getElementById("pcap").classList.add("active");
    document.getElementById("pcap-tab-btn").classList.add("active");
    document.getElementById("pcap-tab-btn").classList.remove("inactive");
  }
}

document.getElementById("start-button").addEventListener("click", function () {
  // Disable nút "Bắt đầu theo dõi"
  this.disabled = true;

  this.classList.add("button-disabled");

  // Xóa lớp "button-active" nếu có
  this.classList.remove("button-active");
  // Enable nút "Dừng theo dõi"
  document.getElementById("stop-button").disabled = false;
  document.getElementById("stop-button").classList.add("button-active");
  document.getElementById("stop-button").classList.remove("button-disabled");

  resultArea = document.getElementById("result");
  resultArea.value +=
    "Đang theo dõi !\n Không có cuộc tấn công DNS cache poisoning";
  resultArea.scrollTop = resultArea.scrollHeight;

  const formData = new FormData(document.getElementById("capture-form"));

  // Gửi dữ liệu form đến server
  fetch("/start_capture", {
    method: "POST",
    body: formData,
  }).catch((error) => {
    console.error("Lỗi:", error);
  });
});

document.getElementById("stop-button").addEventListener("click", function () {
  // Enable lại nút "Bắt đầu theo dõi"
  document.getElementById("start-button").disabled = false;

  // Disable nút "Dừng theo dõi"
  this.disabled = true;
  this.classList.add("button-disabled");

  document.getElementById("start-button").disabled = false;
  document.getElementById("start-button").classList.add("button-active");
  document.getElementById("start-button").classList.remove("button-disabled");

  // Xóa lớp "button-active" nếu có
  this.classList.remove("button-active");
  // Dừng quá trình theo dõi (tùy thuộc vào logic xử lý của bạn)
  stopCapture();
});

function stopCapture() {
  // Logic dừng theo dõi ở đây
  fetch("/stop_capture", {
    method: "GET",
  }).catch((error) => {
    console.error("Lỗi:", error);
  });
  document.getElementById("result").value += "Đã dừng theo dõi.\n";
}

const socket = io();

socket.on("update", function (data) {
  const resultArea = document.getElementById("result");

  const newLine = `${data.result}`;
  resultArea.value += newLine;
  resultArea.scrollTop = resultArea.scrollHeight; // Cuộn xuống cuối textarea
});

document.getElementById("submit-file").addEventListener("click", function () {
  const formData = new FormData(document.getElementById("analyzefile-form"));
  this.disabled = true;

  // Hiển thị hiệu ứng loading
  var loadingMessage = document.getElementById("loading");
  loadingMessage.style.display = "block";
  // clear texarea
  document.getElementById("result_pcap").value = "";
  // Gửi dữ liệu form đến server
  $.ajax({
    url: "/analyze-file",
    type: "POST",
    data: formData,
    processData: false, // Ngăn jQuery tự động xử lý dữ liệu
    contentType: false, // Ngăn jQuery thiết lập content-type
    success: function (response) {
      document.getElementById("result_pcap").value = response.predicted;
      loadingMessage.style.display = "none";
      this.disabled = false;
    },
    error: function (xhr) {
      console.log(xhr);
    },
  });

  // $("/analyze-file", {
  //   method: "POST",
  //   body: formData,
  // })
  //   .then((data) => {
  //     document.getElementById("result_pcap").value = data.result;
  //   })
  //   .catch((error) => {
  //     console.error("Lỗi:", error);
  //   });
});
