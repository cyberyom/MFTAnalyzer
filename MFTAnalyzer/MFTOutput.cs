using System;
using System.IO;
using System.Text;

public class DoubleWriter : TextWriter
{
    private readonly TextWriter first;
    private readonly TextWriter second;

    public DoubleWriter(TextWriter first, TextWriter second)
    {
        this.first = first ?? throw new ArgumentNullException(nameof(first));
        this.second = second ?? throw new ArgumentNullException(nameof(second));
    }
    public override Encoding Encoding => first.Encoding;
    public override void Write(char value)
    {
        first.Write(value);
        second.Write(value);
    }
    public override void WriteLine(string value)
    {
        first.WriteLine(value);
        second.WriteLine(value);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            first.Dispose();
            second.Dispose();
        }
        base.Dispose(disposing);
    }
}
