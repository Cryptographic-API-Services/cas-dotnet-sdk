using CasDotnetSdk.Helpers;
using CasDotnetSdk.Hybrid.Types;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System.Reflection;
using System;
using System.Runtime.InteropServices;
using CasDotnetSdk.Hybrid.Windows;
using CasDotnetSdk.Hybrid.Linux;

namespace CasDotnetSdk.Hybrid
{
    public class HpkeWrapper : BaseWrapper
    {
        public HpkeWrapper()
        {

        }

        public HpkeKeyPairResult GenerateKeyPair()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                HpkeKeyPairResultStruct keyPair = HpkeLinuxWrapper.hpke_generate_keypair();
                byte[] privateKeyResult = new byte[keyPair.private_key_ptr_length];
                byte[] publicKeyResult = new byte[keyPair.public_key_ptr_length];
                Marshal.Copy(keyPair.private_key_ptr, privateKeyResult, 0, keyPair.private_key_ptr_length);
                Marshal.Copy(keyPair.public_key_ptr, publicKeyResult, 0, keyPair.public_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(keyPair.public_key_ptr);
                FreeMemoryHelper.FreeBytesMemory(keyPair.private_key_ptr);
                HpkeKeyPairResult result = new HpkeKeyPairResult()
                {
                    PrivateKey = privateKeyResult,
                    PublicKey = publicKeyResult
                };
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HpkeWrapper));
                return result;
            }
            else
            {
                HpkeKeyPairResultStruct keyPair = HpkeWindowsWrapper.hpke_generate_keypair();
                byte[] privateKeyResult = new byte[keyPair.private_key_ptr_length];
                byte[] publicKeyResult = new byte[keyPair.public_key_ptr_length];
                Marshal.Copy(keyPair.private_key_ptr, privateKeyResult, 0, keyPair.private_key_ptr_length);
                Marshal.Copy(keyPair.public_key_ptr, publicKeyResult, 0, keyPair.public_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(keyPair.public_key_ptr);
                FreeMemoryHelper.FreeBytesMemory(keyPair.private_key_ptr);
                HpkeKeyPairResult result = new HpkeKeyPairResult()
                {
                    PrivateKey = privateKeyResult,
                    PublicKey = publicKeyResult
                };
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HpkeWrapper));
                return result;
            }
        }
    }
}
