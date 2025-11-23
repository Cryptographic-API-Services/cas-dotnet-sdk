using CasDotnetSdk.HTTP;
using MethodDecorator.Fody.Interfaces;
using System;
using System.Diagnostics;
using System.Reflection;
using System.Threading;

namespace CasDotnetSdk.Fodies
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Constructor)]
    internal class BenchmarkSenderAttribute : Attribute, IMethodDecorator
    {
        private Stopwatch watch { get; set; }
        private string methodName { get; set; }
        private string methodClass { get; set; }
        public void Init(object instance, MethodBase method, object[] args)
        {
            this.watch = new Stopwatch();
            this.methodName = method.Name;
            this.methodClass = method.DeclaringType.Name;
        }

        public void OnEntry()
        {
            this.watch.Start();
        }

        public void OnException(Exception exception)
        {

        }

        public void OnExit()
        {
            this.watch.Stop();
            if (this.CanSend())
            {
                HTTPWrapper.SendBenchmarkToApi(this.watch.ElapsedMilliseconds, this.methodClass, this.methodName);
            }
        }

        private bool CanSend()
        {
            bool result = true;
            if (CASConfiguration.ApiKey == null || CASConfiguration.ApiKey.Length == 0)
            {
                result = false;
            }
            return result;
        }
    }
}
