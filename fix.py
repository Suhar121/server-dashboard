import re

with open('index.html', 'r', encoding='utf-8') as f:
    text = f.read()

# remove duplicate updateChartColors (first one is fine)
text = re.sub(r'(\s*function updateChartColors\(theme\).*?\}\n)', r'\1', text, flags=re.DOTALL, count=1) 
# wait, standard re.sub won't easily distinguish. Let's just split and take first occurrence.

while text.count('function updateChartColors(theme)') > 1:
    idx_first = text.find('function updateChartColors(theme)')
    idx_second = text.find('function updateChartColors(theme)', idx_first + 1)
    # find the end of the second function (next function or const)
    idx_end = text.find('const chartCtx', idx_second)
    text = text[:idx_second] + text[idx_end:]
    
while text.count('const initialTheme = document.documentElement.getAttribute(\'data-theme\') ||') > 1:
    idx_first = text.find('const initialTheme = document.documentElement.getAttribute(\'data-theme\')')
    idx_second = text.find('const initialTheme = document.documentElement.getAttribute(\'data-theme\')', idx_first + 1)
    
    idx_end = text.find('function showLogin', idx_second)
    text = text[:idx_second] + text[idx_end:]

with open('index.html', 'w', encoding='utf-8') as f:
    f.write(text)

