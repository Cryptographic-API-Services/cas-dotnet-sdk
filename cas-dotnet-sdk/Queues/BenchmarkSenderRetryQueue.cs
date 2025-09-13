using CasDotnetSdk.Http;
using CasDotnetSdk.Types;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CasDotnetSdk.Queues
{
    internal class BenchmarkSenderRetryQueue
    {
        private ConcurrentQueue<BenchmarkMacAddressSDKMethod> Queue { get; set; }
        private Timer Timer { get; set; }
        private int Interval { get; set; }
        public BenchmarkSenderRetryQueue()
        {
            this.Queue = new ConcurrentQueue<BenchmarkMacAddressSDKMethod>();
            this.Interval = 45;
            this.Timer = new Timer(CheckQueueForRequestsToSend, null, TimeSpan.FromSeconds(this.Interval), TimeSpan.FromSeconds(this.Interval));
        }

        public void Enqueue(BenchmarkMacAddressSDKMethod method)
        {
            method.NumberOfTries = 0;
            this.Queue.Enqueue(method);
        }

        /// <summary>
        /// Checks if queue has any entries and attempts to empty. If not success status code from HTTP Post put back into queue for new time.
        /// </summary>
        /// <param name="state"></param>
        private async void CheckQueueForRequestsToSend(object state)
        {
            if (this.Queue.Count > 0)
            {
                await Task.Run(async () =>
                {
                    List<BenchmarkMacAddressSDKMethod> addBackToQueue = new List<BenchmarkMacAddressSDKMethod>();
                    BenchmarkSender newSender = new BenchmarkSender();
                    List<Tuple<Task<bool>, BenchmarkMacAddressSDKMethod>> requestSuccess = new();
                    foreach (BenchmarkMacAddressSDKMethod method in this.Queue)
                    {
                        BenchmarkMacAddressSDKMethod retryBnechmark = null;
                        if (this.Queue.TryDequeue(out retryBnechmark))
                        {
                            var tuple = new Tuple<Task<bool>, BenchmarkMacAddressSDKMethod>(newSender.SendNewBenchmarkMethodRetry(retryBnechmark), retryBnechmark);
                            requestSuccess.Add(tuple);
                        }
                    }

                    bool[] results = await Task.WhenAll(requestSuccess.ToList().Select(x => x.Item1));
                    for (int i = 0; i < results.Length; i++)
                    {
                        if (!results[i])
                        {
                            addBackToQueue.Add(requestSuccess[i].Item2);
                        }
                    }

                    // Check if any failed and place back into queue
                    if (addBackToQueue.Count > 0)
                    {
                        foreach (BenchmarkMacAddressSDKMethod method in addBackToQueue)
                        {
                            method.NumberOfTries++;
                            if (method.NumberOfTries > 2)
                            {
                                this.Enqueue(method);
                            }
                        }
                    }
                });
            }
        }
    }
}
