// Real-time canvas telemetry graph matching RoutePulse SOC Slide 4 Event Timeline

class ThreatTimelineChart {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    // Telemetry series
    this.pointsCount = 35;
    this.criticalSeries = [];
    this.warningSeries = [];
    this.infoSeries = [];

    this.initData();
    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.render();
  }

  initData() {
    for (let i = 0; i < this.pointsCount; i++) {
      this.criticalSeries.push(Math.floor(Math.sin(i * 0.4) * 8 + 12 + Math.random() * 6));
      this.warningSeries.push(Math.floor(Math.cos(i * 0.3) * 15 + 28 + Math.random() * 10));
      this.infoSeries.push(Math.floor(45 + Math.random() * 20));
    }
  }

  pushPoint(isCritical, isWarning) {
    const lastCrit = this.criticalSeries[this.criticalSeries.length - 1];
    const lastWarn = this.warningSeries[this.warningSeries.length - 1];

    let newCrit = lastCrit + (Math.random() * 6 - 3);
    if (isCritical) newCrit += 12;
    newCrit = Math.max(4, Math.min(newCrit, 45));

    let newWarn = lastWarn + (Math.random() * 8 - 4);
    if (isWarning) newWarn += 15;
    newWarn = Math.max(10, Math.min(newWarn, 65));

    this.criticalSeries.shift();
    this.criticalSeries.push(newCrit);

    this.warningSeries.shift();
    this.warningSeries.push(newWarn);

    this.render();
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width * window.devicePixelRatio;
    this.canvas.height = 200 * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    this.render();
  }

  render() {
    if (!this.ctx) return;
    const width = this.canvas.width / window.devicePixelRatio;
    const height = 200;
    const ctx = this.ctx;

    ctx.clearRect(0, 0, width, height);

    // Draw background grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
    ctx.lineWidth = 1;
    for (let y = 30; y < height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    const step = width / (this.pointsCount - 1);
    const maxY = 70;

    // 1. Draw Warning Area (Amber)
    this.drawLine(this.warningSeries, '#f59e0b', 'rgba(245, 158, 11, 0.12)', step, height, maxY);

    // 2. Draw Critical Area (Red)
    this.drawLine(this.criticalSeries, '#ef4444', 'rgba(239, 68, 68, 0.20)', step, height, maxY);
  }

  drawLine(data, strokeColor, fillColor, step, height, maxY) {
    const ctx = this.ctx;
    ctx.beginPath();
    ctx.moveTo(0, height - (data[0] / maxY) * (height - 30));

    for (let i = 1; i < data.length; i++) {
      const x = i * step;
      const y = height - (data[i] / maxY) * (height - 30);
      const prevX = (i - 1) * step;
      const prevY = height - (data[i - 1] / maxY) * (height - 30);
      const cx = (prevX + x) / 2;
      ctx.bezierCurveTo(cx, prevY, cx, y, x, y);
    }

    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Fill gradient
    ctx.lineTo((data.length - 1) * step, height);
    ctx.lineTo(0, height);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();
  }
}
