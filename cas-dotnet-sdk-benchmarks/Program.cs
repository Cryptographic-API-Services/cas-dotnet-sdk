// See https://aka.ms/new-console-template for more information




using BenchmarkDotNet.Running;
using CASBenchmarks;

var passwordSummary = BenchmarkRunner.Run<PasswordHashBenchmark>();
