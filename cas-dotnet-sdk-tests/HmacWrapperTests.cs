﻿using CasDotnetSdk.Hashers;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class HmacWrapperTests
    {
        private HmacWrapper _hmacWrapper { get; set; }
        public HmacWrapperTests()
        {
            this._hmacWrapper = new HmacWrapper();
        }

        [Fact]
        public void HmacSignBytes()
        {
            byte[] key = Encoding.UTF8.GetBytes("HmacKey");
            byte[] message = Encoding.UTF8.GetBytes("message to sign");
            byte[] signature = this._hmacWrapper.HmacSignBytes(key, message);
            Assert.NotNull(signature);
            Assert.NotEmpty(signature);
            Assert.NotEqual(signature, message);
        }

        [Fact]
        public void HmacVerifyBytes()
        {
            byte[] key = Encoding.ASCII.GetBytes("HmacKey");
            byte[] message = Encoding.ASCII.GetBytes("message to sign");
            byte[] signature = this._hmacWrapper.HmacSignBytes(key, message);
            bool isValid = this._hmacWrapper.HmacVerifyBytes(key, message, signature);
            Assert.True(isValid);
        }
    }
}
