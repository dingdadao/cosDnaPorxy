// charts.js — 商用化差距与优化路线图
(function () {
  var style = getComputedStyle(document.documentElement);
  var accent = style.getPropertyValue('--accent').trim();
  var accent2 = style.getPropertyValue('--accent2').trim();
  var ink = style.getPropertyValue('--ink').trim();
  var muted = style.getPropertyValue('--muted').trim();
  var rule = style.getPropertyValue('--rule').trim();
  var bg2 = style.getPropertyValue('--bg2').trim();
  var ok = style.getPropertyValue('--ok').trim();
  var warn = style.getPropertyValue('--warn').trim();
  var bad = style.getPropertyValue('--bad').trim();

  // ---------- 图 1：四维成熟度雷达 ----------
  var radarEl = document.getElementById('chart-radar');
  if (radarEl) {
    var radar = echarts.init(radarEl, null, { renderer: 'svg' });
    radar.setOption({
      animation: false,
      color: [accent, accent2],
      tooltip: { appendToBody: true },
      legend: { top: 0, textStyle: { color: ink } },
      radar: {
        indicator: [
          { name: '性能', max: 5 },
          { name: '容错与可靠性', max: 5 },
          { name: '防污染与解析正确性', max: 5 },
          { name: '公网服务能力与安全', max: 5 }
        ],
        radius: '62%',
        axisName: { color: muted, fontSize: 13 },
        splitLine: { lineStyle: { color: rule } },
        splitArea: { areaStyle: { color: [bg2, '#ffffff'] } },
        axisLine: { lineStyle: { color: rule } }
      },
      series: [{
        type: 'radar',
        name: '本系统现状',
        symbolSize: 6,
        lineStyle: { width: 2.5, color: accent },
        areaStyle: { opacity: 0.16, color: accent },
        itemStyle: { color: accent },
        data: [{ value: [3.0, 2.6, 2.6, 2.2] }]
      }, {
        type: 'radar',
        name: '商用基线',
        symbolSize: 5,
        lineStyle: { width: 2, type: 'dashed', color: accent2 },
        areaStyle: { opacity: 0.06, color: accent2 },
        itemStyle: { color: accent2 },
        data: [{ value: [5, 4.6, 4.7, 4.5] }]
      }]
    });
    window.addEventListener('resize', function () { radar.resize(); });
  }

  // ---------- 图 3：差距优先级分布 ----------
  var gapEl = document.getElementById('chart-gap');
  if (gapEl) {
    var gap = echarts.init(gapEl, null, { renderer: 'svg' });
    gap.setOption({
      animation: false,
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, appendToBody: true },
      legend: { top: 0, textStyle: { color: ink } },
      grid: { left: 110, right: 30, top: 46, bottom: 24 },
      xAxis: { type: 'value', name: '差距项数量', nameTextStyle: { color: muted }, axisLabel: { color: muted }, splitLine: { lineStyle: { color: rule } } },
      yAxis: {
        type: 'category',
        data: ['公网服务能力与安全', '防污染与解析正确性', '容错与可靠性', '性能'],
        axisLabel: { color: ink, fontSize: 13 },
        axisLine: { lineStyle: { color: rule } }
      },
      series: [
        {
          name: 'P0 阻断', type: 'bar', stack: 'total', barWidth: 26,
          itemStyle: { color: bad }, label: { show: true, color: '#fff', fontSize: 11 },
          data: [3, 2, 1, 2]
        },
        {
          name: 'P1 重要', type: 'bar', stack: 'total', barWidth: 26,
          itemStyle: { color: warn }, label: { show: true, color: '#fff', fontSize: 11 },
          data: [3, 3, 3, 3]
        },
        {
          name: 'P2 增强', type: 'bar', stack: 'total', barWidth: 26,
          itemStyle: { color: accent }, label: { show: true, color: '#fff', fontSize: 11 },
          data: [1, 0, 2, 0]
        }
      ]
    });
    window.addEventListener('resize', function () { gap.resize(); });
  }
})();
