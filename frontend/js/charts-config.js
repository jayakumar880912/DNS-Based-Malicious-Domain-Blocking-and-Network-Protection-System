/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Chart.js Cyber Theme Configurations and Rendering Utilities
 */

const CyberCharts = (() => {
  // Chart instances registry to avoid duplicate contexts
  const instances = {};

  // Default Chart.js global dark theme styles
  const applyCyberDefaults = () => {
    if (typeof Chart === 'undefined') return;

    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(11, 20, 39, 0.95)';
    Chart.defaults.plugins.tooltip.titleColor = '#00f0ff';
    Chart.defaults.plugins.tooltip.bodyColor = '#f1f5f9';
    Chart.defaults.plugins.tooltip.borderColor = 'rgba(0, 240, 255, 0.3)';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 12;
    Chart.defaults.plugins.tooltip.boxPadding = 6;
    Chart.defaults.plugins.tooltip.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.boxWidth = 8;
  };

  return {
    /**
     * Render the 24-hour DNS Request Activity Line/Area Chart
     */
    initTrafficChart(canvasId, trafficData) {
      if (typeof Chart === 'undefined') return null;
      applyCyberDefaults();

      const canvas = document.getElementById(canvasId);
      if (!canvas) return null;

      if (instances[canvasId]) {
        instances[canvasId].destroy();
      }

      const ctx = canvas.getContext('2d');

      // Create glowing neon gradients
      const cyanGrad = ctx.createLinearGradient(0, 0, 0, 300);
      cyanGrad.addColorStop(0, 'rgba(0, 240, 255, 0.35)');
      cyanGrad.addColorStop(1, 'rgba(0, 240, 255, 0.0)');

      const redGrad = ctx.createLinearGradient(0, 0, 0, 300);
      redGrad.addColorStop(0, 'rgba(255, 51, 102, 0.4)');
      redGrad.addColorStop(1, 'rgba(255, 51, 102, 0.0)');

      const chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: trafficData.labels,
          datasets: [
            {
              label: 'Total DNS Queries',
              data: trafficData.totalRequests,
              borderColor: '#00f0ff',
              backgroundColor: cyanGrad,
              borderWidth: 2.5,
              tension: 0.38,
              fill: true,
              pointBackgroundColor: '#00f0ff',
              pointBorderColor: '#050811',
              pointRadius: 4,
              pointHoverRadius: 7
            },
            {
              label: 'Blocked Malicious',
              data: trafficData.blockedRequests,
              borderColor: '#ff3366',
              backgroundColor: redGrad,
              borderWidth: 2,
              tension: 0.38,
              fill: true,
              pointBackgroundColor: '#ff3366',
              pointBorderColor: '#050811',
              pointRadius: 3,
              pointHoverRadius: 6
            },
            {
              label: 'Suspicious Domains',
              data: trafficData.suspiciousRequests,
              borderColor: '#f59e0b',
              backgroundColor: 'transparent',
              borderWidth: 1.8,
              borderDash: [5, 5],
              tension: 0.38,
              fill: false,
              pointBackgroundColor: '#f59e0b',
              pointRadius: 3,
              pointHoverRadius: 5
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            mode: 'index',
            intersect: false
          },
          plugins: {
            legend: {
              position: 'top',
              align: 'end',
              labels: {
                color: '#cbd5e1',
                font: { size: 12, weight: '500' }
              }
            }
          },
          scales: {
            x: {
              grid: {
                color: 'rgba(148, 163, 184, 0.07)',
                drawBorder: false
              },
              ticks: {
                font: { family: "'JetBrains Mono', monospace", size: 11 }
              }
            },
            y: {
              grid: {
                color: 'rgba(148, 163, 184, 0.07)',
                drawBorder: false
              },
              ticks: {
                font: { family: "'JetBrains Mono', monospace", size: 11 },
                callback: function (val) {
                  return val >= 1000 ? (val / 1000) + 'k' : val;
                }
              }
            }
          }
        }
      });

      instances[canvasId] = chart;
      return chart;
    },

    /**
     * Render the Threat Classification Donut Chart
     */
    initThreatCategoriesChart(canvasId, categoriesData) {
      if (typeof Chart === 'undefined') return null;
      applyCyberDefaults();

      const canvas = document.getElementById(canvasId);
      if (!canvas) return null;

      if (instances[canvasId]) {
        instances[canvasId].destroy();
      }

      const ctx = canvas.getContext('2d');

      const chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: categoriesData.labels,
          datasets: [
            {
              data: categoriesData.data,
              backgroundColor: categoriesData.colors || [
                '#ff3366', // Phishing
                '#ff7b00', // C2 Botnet
                '#a855f7', // DGA
                '#00f0ff', // Cryptomining
                '#eab308'  // Ransomware
              ],
              borderColor: '#0b1427',
              borderWidth: 3,
              hoverOffset: 8
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#94a3b8',
                padding: 16,
                font: { size: 11 }
              }
            }
          }
        }
      });

      instances[canvasId] = chart;
      return chart;
    },

    /**
     * Render Severity Breakdown Bar Chart for Threat Detection Page
     */
    initSeverityBarChart(canvasId) {
      if (typeof Chart === 'undefined') return null;
      applyCyberDefaults();

      const canvas = document.getElementById(canvasId);
      if (!canvas) return null;

      if (instances[canvasId]) {
        instances[canvasId].destroy();
      }

      const ctx = canvas.getContext('2d');

      const chart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: ['Critical Severity', 'High Severity', 'Medium Severity', 'Low Risk'],
          datasets: [
            {
              label: 'Active Threat Signatures',
              data: [5420, 18400, 34790, 40030],
              backgroundColor: [
                'rgba(255, 51, 102, 0.85)',
                'rgba(255, 123, 0, 0.85)',
                'rgba(245, 158, 11, 0.85)',
                'rgba(234, 179, 8, 0.75)'
              ],
              borderColor: [
                '#ff3366',
                '#ff7b00',
                '#f59e0b',
                '#eab308'
              ],
              borderWidth: 1.5,
              borderRadius: 6
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: '#cbd5e1' }
            },
            y: {
              grid: { color: 'rgba(148, 163, 184, 0.07)' },
              ticks: {
                font: { family: "'JetBrains Mono', monospace" },
                callback: (val) => val >= 1000 ? (val / 1000) + 'k' : val
              }
            }
          }
        }
      });

      instances[canvasId] = chart;
      return chart;
    }
  };
})();

// Export to window
if (typeof window !== 'undefined') {
  window.CyberCharts = CyberCharts;
}

