# report_canvas.py
from reportlab.pdfgen import canvas
from reportlab.lib import colors

SOC_MUTED = colors.HexColor("#94A3B8")
SOC_LINE = colors.HexColor("#CBD5E1")
CLASS_BANNER = "CONFIDENTIAL - SOC / LEGAL HOLD"


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_states = []

    def showPage(self):
        self._saved_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_states)
        for state in self._saved_states:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, total):
        w, _ = self._pagesize
        self.setStrokeColor(SOC_LINE)
        self.setLineWidth(0.4)
        self.line(36, 42, w - 36, 42)

        self.setFont("Helvetica", 8)
        self.setFillColor(SOC_MUTED)
        self.drawString(36, 28, CLASS_BANNER)
        self.drawRightString(w - 36, 28, "Page {} of {}".format(self._pageNumber, total))