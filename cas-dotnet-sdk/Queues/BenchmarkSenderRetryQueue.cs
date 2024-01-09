using CasDotnetSdk.Http;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace CasDotnetSdk.Queues
{
    internal class BenchmarkSenderRetryQueue
    {
        private ConcurrentQueue<BenchmarkSDKMethod> Queue { get; set; }
        private Timer Timer { get; set; }
        private int Interval { get; set; }
        public BenchmarkSenderRetryQueue()
        {
            this.Queue = new ConcurrentQueue<BenchmarkSDKMethod>();
            this.Interval = 30;
            this.Timer = new Timer(CheckQueueForRequestsToSend, null, TimeSpan.FromSeconds(this.Interval), TimeSpan.FromSeconds(this.Interval));
        }

        public void Enqueue(BenchmarkSDKMethod method)
        {
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
                    List<BenchmarkSDKMethod> addBackToQueue = new List<BenchmarkSDKMethod>();
                    foreach (BenchmarkSDKMethod method in this.Queue)
                    {
                        BenchmarkSDKMethod retryBnechmark = null;
                        if (this.Queue.TryDequeue(out retryBnechmark))
                        {
                            BenchmarkSender newSender = new BenchmarkSender();
                            bool result = await newSender.SendNewBenchmarkMethodRetry(retryBnechmark);
                            if (!result)
                            {
                                addBackToQueue.Add(retryBnechmark);
                            }
                        }
                    }
                    // Check if any failed and place back into queue
                    if (addBackToQueue.Count > 0)
                    {
                        foreach (BenchmarkSDKMethod method in addBackToQueue)
                        {
                            this.Enqueue(method);
                        } 
                    }
                });
            }
        }
    }
}
