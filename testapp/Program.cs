using System;
using System.Reflection;
using System.Threading;

Console.WriteLine("Test .NET Core Application");
Console.WriteLine($"PID: {Environment.ProcessId}");
Console.WriteLine();

// List loaded assemblies
Console.WriteLine("Loaded Assemblies:");
foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
{
    Console.WriteLine($"  - {asm.GetName().Name}");
}

Console.WriteLine();
Console.WriteLine("Press Ctrl+C to exit...");

// Keep running
while (true)
{
    Thread.Sleep(1000);
}
