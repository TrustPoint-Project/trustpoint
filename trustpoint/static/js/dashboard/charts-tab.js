function drawNoDataMessageOnCanvas(canvas) {
    const context = canvas.getContext("2d");
    // Clear any previous content on the canvas
    context.clearRect(0, 0, canvas.width, canvas.height);

    // Set font style and alignment for the message
    context.font = "20px tpQuicksand, sans-serif";
    context.fillStyle = "#444"; // Set a color for the message text
    context.textAlign = "center";
    context.textBaseline = "middle";

    // Display the "No Data Available" message at the center of the canvas
    context.fillText(gettext("No data available"), canvas.width / 2, canvas.height / 2);
}

function getFriendlyLabel(key) {
    const labels = {
        'total': gettext('Total'),
        // Onboarding status
        'pending': gettext('Pending'),
        'running': gettext('Running'),
        'onboarded': gettext('Onboarded'),
        'failed': gettext('Failed'),
        'revoked': gettext('Revoked'),
        // Certificate status
        'OK': gettext('OK'),
        'REV': gettext('Revoked'),
        'EXP': gettext('Expired'),
        'NYV': gettext('Not Yet Valid'),
        // CA localizations
        'local': gettext('Local'),
        'remote': gettext('Remote'),
        'autogen': gettext('Auto-gen PKI'),
    }

    return labels[key] || key;
}

function updateCertsByStatusLineChart(certStatusCounts) {
    const canvas = document.getElementById("certsByStatusLineChart");
    const certsByStatusLineChartEle = canvas.getContext("2d");

    if (!certStatusCounts || certStatusCounts.length === 0) {
        return drawNoDataMessageOnCanvas(canvas);
    }

    if (certsByStatusLineChart) {
        certsByStatusLineChart.destroy();
    }

    // Extrahiere einzigartige Datumswerte für die X-Achse
    const chartLabels = [...new Set(certStatusCounts.map(item => item.issue_date))];

    

    // Gruppiere die Daten nach Zertifikatsstatus
    const datasets = {};
    certStatusCounts.forEach(item => {
        if (!datasets[item.certificate_status]) {
            datasets[item.certificate_status] = {
                label: item.certificate_status,
                data: Array(chartLabels.length).fill(0),
                // Optional: Farbe für jeden Status festlegen
                // backgroundColor: getRandomColor(),
            };
        }
        const index = chartLabels.indexOf(item.issue_date);
        datasets[item.certificate_status].data[index] = item.cert_count;
    });

    const chartDatasets = Object.values(datasets);

    const friendlyLabels = chartDatasets.map(dataset => getFriendlyLabel(dataset.label));
    console.log(friendlyLabels);

    certsByStatusLineChart = new Chart(certsByStatusLineChartEle, {
        type: "line",
        data: {
            labels: friendlyLabels,
            datasets: chartDatasets,
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                },
            },
        },
    });
}

// Function to update the issuing ca certificate stack chart
function updateDeviceDateChart(deviceDateCounts) {
    var canvas = document.getElementById("devicesByOSLineChart");
    var devicesByOSLineChartEle = canvas.getContext("2d");
    if (!deviceDateCounts) {
        return drawNoDataMessageOnCanvas(canvas);
    }
    devicesByOSLineChart != undefined ? devicesByOSLineChart.destroy() : "";

    const chartLabels = [...new Set(deviceDateCounts.map((item) => item.issue_date))]; // Unique dates
    const datasets = {};

    // Group data by 'onboarding_status'
    deviceDateCounts.forEach((item) => {
        if (!datasets[item.onboarding_status]) {
        datasets[item.onboarding_status] = {
            label: item.onboarding_status,
            data: Array(chartLabels.length).fill(0), // Initialize count for each date
            //stack: "stack",
            //backgroundColor: getRandomColor(), // Random color for each dataset
        };
        }
        const index = chartLabels.indexOf(item.issue_date);
        datasets[item.onboarding_status].data[index] += item.device_count; // Accumulate counts
    });
    // Convert datasets object to array for Chart.js
    const chartDatasets = Object.values(datasets);
    devicesByOSLineChart = new Chart(devicesByOSLineChartEle, {
        type: "line",
        data: {
        labels: chartLabels,
        datasets: chartDatasets,
        },
        options: {
        scales: {
            y: {
            beginAtZero: "true",
            },
        },
        },
    });
}

// Function to update the devices by onboarding status bar chart
function updateDeviceByOSBarChart(deviceOSCounts) {
  const canvas = document.getElementById("devicesByOSLineChart");
  var devicesByOSLineChartEle = canvas.getContext("2d");
  if (!deviceOSCounts) {
    return drawNoDataMessageOnCanvas(canvas);
  }
  devicesByOSLineChart != undefined ? devicesByOSLineChart.destroy() : "";
  var chartLabels = [];
  var chartData = [];
  Object.entries(deviceOSCounts).forEach(([key, value]) => {
    chartLabels.push(getFriendlyLabel(key));
    chartData.push(value);
  });
  devicesByOSLineChart = new Chart(devicesByOSLineChartEle, {
    type: "bar",
    data: {
      labels: chartLabels,
      datasets: [
        {
          label: gettext("Number of Devices"),
          data: chartData,
          //borderColor: "#0d6efd",
          //backgroundColor: "#0d6efd",
          backgroundColor: [
            'rgba(255, 99, 132, 0.8)', // Red
            'rgba(54, 162, 235, 0.8)', // Blue
            'rgba(255, 206, 86, 0.8)', // Yellow
            'rgba(75, 192, 192, 0.8)', // Green
            'rgba(153, 102, 255, 0.8)', // Purple
            'rgba(255, 159, 64, 0.8)'   // Orange
        ],
        borderColor: [
            'rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)',
            'rgba(255, 206, 86, 1)',
            'rgba(75, 192, 192, 1)',
            'rgba(153, 102, 255, 1)',
            'rgba(255, 159, 64, 1)'
        ],
          tension: 0.4,
          fill: "true",
        },
      ],
    },
    options: {
      indexAxis: "y",
      scales: {
        x: {ticks: {precision: 0}},
        y: {
          beginAtZero: "true",
        },
      },
    },
  });
}

// Function to update the devices by onboarding protocol line chart
function updateDeviceByOPLineChart(deviceOPCounts) {
    const canvas = document.getElementById("devicesByOPBarChart");
    var devicesByOPBarChartEle = canvas.getContext("2d");
    if (!deviceOPCounts) {
        return drawNoDataMessageOnCanvas(canvas);
    }
    devicesByOPBarChart != undefined ? devicesByOPBarChart.destroy() : "";
    var chartLabels = [];
    var chartData = [];
    Object.entries(deviceOPCounts).forEach(([key, value]) => {
        chartLabels.push(key);
        chartData.push(value);
    });
    devicesByOPBarChart = new Chart(devicesByOPBarChartEle, {
        type: "bar",
        data: {
        labels: chartLabels,
        datasets: [
            {
            label: gettext("Number of Devices"),
            data: chartData,
            borderColor: "#0d6efd",
            backgroundColor: "#0d6efd",
            tension: 0.4,
            fill: "true",
            },
        ],
        },
        options: {
        scales: {
            y: {
            beginAtZero: "true",
            },
        },
        },
    });
}

// Function to update the devices by domain donut chart
function updateDevicesByDomainDonutChart(deviceDomainCounts) {
    const canvas = document.getElementById("devicesByDomainDonutChart");
    const devicesByDomainDonutChartEle = canvas.getContext("2d");

    if (!deviceDomainCounts || deviceDomainCounts.length === 0) {
        return drawNoDataMessageOnCanvas(canvas);
    }

    if (devicesByDomainDonutChart) {
        devicesByDomainDonutChart.destroy();
    }

    const chartLabels = [];
    const chartData = [];

    deviceDomainCounts.forEach((item) => {
        chartLabels.push(item.unique_name);
        chartData.push(item.onboarded_device_count); // Feldname angepasst
    });


    devicesByDomainDonutChart = new Chart(devicesByDomainDonutChartEle, {
        type: "doughnut",
        data: {
            labels: chartLabels,
            datasets: [
                {
                    data: chartData,
                    borderWidth: 1,
                    hoverOffset: 4,
                },
            ],
        },
    });
}

// Function to update the certs by status bar chart
function updateCertsByStatusBarChart(certStatusCounts) {
  const canvas = document.getElementById("certsByStatusLineChart");
  const certsByStatusLineChartEle = canvas.getContext("2d");

  if (!certStatusCounts) {
    return drawNoDataMessageOnCanvas(canvas);
  }
  certsByStatusLineChart != undefined ? certsByStatusLineChart.destroy() : "";
  var chartLabels = [];
  var chartData = [];
  Object.entries(certStatusCounts).forEach(([key, value]) => {
    chartLabels.push(getFriendlyLabel(key));
    chartData.push(value);
  });
  certsByStatusLineChart = new Chart(certsByStatusLineChartEle, {
    type: "bar",
    data: {
      labels: chartLabels,
      datasets: [
        {
          label: gettext("Number of Certificates"),
          data: chartData,
          //borderColor: "#0d6efd",
          //backgroundColor: "#0d6efd",
          backgroundColor: [
            'rgba(255, 99, 132, 0.8)', // Red
            'rgba(54, 162, 235, 0.8)', // Blue
            // 'rgba(255, 206, 86, 0.8)', // Yellow
            // 'rgba(75, 192, 192, 0.8)', // Green
            // 'rgba(153, 102, 255, 0.8)', // Purple
            // 'rgba(255, 159, 64, 0.8)'   // Orange
        ],
        borderColor: [
            'rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)',
            // 'rgba(255, 206, 86, 1)',
            // 'rgba(75, 192, 192, 1)',
            // 'rgba(153, 102, 255, 1)',
            // 'rgba(255, 159, 64, 1)'
        ],
          tension: 0.4,
          fill: "true",
        },
      ],
    },
    options: {
      indexAxis: "y",
      scales: {
        x: {ticks: {precision: 0}},
        y: {
          beginAtZero: "true",
        },
      },
    },
  });
}

// Function to update the certificates by domain pie chart
function updateCertsByDomainPieChart(certDomainCounts) {
    const canvas = document.getElementById("certsByDomainPieChart");
    var certsByDomainPieChartEle = canvas.getContext("2d");
    if (!certDomainCounts) {
        return drawNoDataMessageOnCanvas(canvas);
    }
    certsByDomainPieChart != undefined ? certsByDomainPieChart.destroy() : "";
    var chartLabels = [];
    var chartData = [];
    certDomainCounts.forEach((item) => {
        chartLabels.push(item.unique_name);
        chartData.push(item.cert_count);
    });
    certsByDomainPieChart = new Chart(certsByDomainPieChartEle, {
        type: "doughnut",
        data: {
        labels: chartLabels,
        datasets: [
            {
            data: chartData,
            borderWidth: 1,
            //backgroundColor: ["#0d6efd", "#ffc107", "#d10c15"],
            hoverOffset: 4,
            },
        ],
        },
    });
}

// Function to update the certy by template bar chart
function updateCertsByTemplateBarChart(certsByTempateCounts) {
    const canvas = document.getElementById("certsByTemplateBarChart");
    var certsByTemplateBarChartEle = canvas.getContext("2d");
    if (!certsByTempateCounts) {
        return drawNoDataMessageOnCanvas(canvas);
    }
    certsByTemplateBarChart != undefined ? certsByTemplateBarChart.destroy() : "";
    var chartLabels = [];
    var chartData = [];
    Object.entries(certsByTempateCounts).forEach(([key, value]) => {
        chartLabels.push(key);
        chartData.push(value);
    });
    certsByTemplateBarChart = new Chart(certsByTemplateBarChartEle, {
        type: "bar",
        data: {
        labels: chartLabels,
        datasets: [
            {
            label: gettext("Number of Certificates"),
            data: chartData,
            borderColor: "#0d6efd",
            backgroundColor: "#0d6efd",
            tension: 0.4,
            fill: "true",
            },
        ],
        },
        options: {
        scales: {
            y: {
            beginAtZero: "true",
            },
        },
        },
    });
}

// Function to update the issuing ca counts
function updateCertsByIssuingCAChart(certIssuingCACounts) {
    const canvas = document.getElementById("certsByIssuingCADonutChart");
    var certsByIssuingCADonutChartEle = canvas.getContext("2d");
    if (!certIssuingCACounts) {
        return drawNoDataMessageOnCanvas(canvas);
    }
    certsByIssuingCADonutChart != undefined ? certsByIssuingCADonutChart.destroy() : "";
    var chartLabels = [];
    var chartData = [];
    certIssuingCACounts.forEach((item) => {
        chartLabels.push(item.ca_name);
        chartData.push(item.cert_count);
    });
    certsByIssuingCADonutChart = new Chart(certsByIssuingCADonutChartEle, {
        type: "doughnut",
        data: {
        labels: chartLabels,
        datasets: [
            {
            data: chartData,
            borderWidth: 1,
            //backgroundColor: ["#0d6efd", "#ffc107", "#d10c15"],
            hoverOffset: 4,
            },
        ],
        },
        options: {  
            scales: {y: {ticks: {precision: 0}}}
        }
    });
}

// Function to update the issuing ca certificate stack chart
function updateCertsByDateStackChart(certDateCounts) {
    const canvas = document.getElementById("certsByDateStackChart");
    var certsByDateStackChartEle = canvas.getContext("2d");
    if (!certDateCounts) {
        return drawNoDataMessageOnCanvas(canvas);
    }
    certsByDateStackChart != undefined ? certsByDateStackChart.destroy() : "";

    const chartLabels = [...new Set(certDateCounts.map((item) => item.issue_date))]; // Unique dates
    const datasets = {};

    // Group data by 'name'
    certDateCounts.forEach((item) => {
        if (!datasets[item.name]) {
        datasets[item.name] = {
            label: item.name,
            data: Array(chartLabels.length).fill(0), // Initialize count for each date
            stack: "stack",
            //backgroundColor: getRandomColor(), // Random color for each dataset
        };
        }
        const index = chartLabels.indexOf(item.issue_date);
        datasets[item.name].data[index] += item.cert_count; // Accumulate counts
    });
    // Convert datasets object to array for Chart.js
    const chartDatasets = Object.values(datasets);
    certsByDateStackChart = new Chart(certsByDateStackChartEle, {
        type: "bar",
        data: {
        labels: chartLabels,
        datasets: chartDatasets,
        },
        options: {
        scales: {
            y: {
                beginAtZero: "true",
                ticks: {precision: 0}
            },
        },
        },
    });
}

// Function to update the issuing ca pie chart
function updateIssuingCAsByTypePieChart(issuingCaTypeCounts) {
    const canvas = document.getElementById("issuingCAsByTypePieChart");
    var issuingCAsByTypePieChartEle = canvas.getContext("2d");
    if (!issuingCaTypeCounts) {
        return drawNoDataMessageOnCanvas(canvas);
    }
    issuingCAsByTypePieChart != undefined ? issuingCAsByTypePieChart.destroy() : "";
    var chartLabels = [];
    var chartData = [];
    Object.entries(issuingCaTypeCounts).forEach(([key, value]) => {
        chartLabels.push(getFriendlyLabel(key));
        chartData.push(value);
    });
    issuingCAsByTypePieChart = new Chart(issuingCAsByTypePieChartEle, {
        type: "pie",
        data: {
        labels: chartLabels,
        datasets: [
            {
            data: chartData,
            borderWidth: 1,
            //backgroundColor: ["#0d6efd", "#ffc107", "#d10c15"],
            hoverOffset: 4,
            },
        ],
        },
    });
}
