import re

with open('index.html', 'r', encoding='utf-8') as f:
    content = f.read()

chart_update_fn = """    function updateChartColors(theme) {
      if (!cpuChart) return;
      
      const isDark = theme === 'dark';
      const tickColor = isDark ? "#94a3b8" : "#5b6b86";
      const gridColor = isDark ? "rgba(255,255,255,0.06)" : "rgba(15,23,42,0.06)";
      const legendColor = isDark ? "#e2e8f0" : "#0f172a";
      const borderColor = isDark ? "#3b82f6" : "#2563eb";
      const bgColor = isDark ? "rgba(59,130,246,0.18)" : "rgba(37,99,235,0.18)";

      cpuChart.data.datasets[0].borderColor = borderColor;
      cpuChart.data.datasets[0].backgroundColor = bgColor;
      
      cpuChart.options.scales.x.ticks.color = tickColor;
      cpuChart.options.scales.x.grid.color = gridColor;
      cpuChart.options.scales.y.ticks.color = tickColor;
      cpuChart.options.scales.y.grid.color = gridColor;
      
      cpuChart.options.plugins.legend.labels.color = legendColor;
      
      cpuChart.update();
    }

    const chartCtx = document.getElementById("cpuChart").getContext("2d");"""

content = content.replace('    const chartCtx = document.getElementById("cpuChart").getContext("2d");', chart_update_fn)

# Also apply the initial colors based on whatever theme is currently active
init_call = """
    const initialTheme = document.documentElement.getAttribute('data-theme') || 'light';
    updateChartColors(initialTheme);
"""

# inject this right after `const cpuChart = new Chart(...)`
end_chart = '    });\n'
chart_init_end = content.find(end_chart, content.find('const cpuChart = new Chart')) + len(end_chart)
content = content[:chart_init_end] + init_call + content[chart_init_end:]


with open('index.html', 'w', encoding='utf-8') as f:
    f.write(content)

