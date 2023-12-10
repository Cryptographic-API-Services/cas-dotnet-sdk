﻿using CasDotnetSdk.Hashers;
using CasDotnetSdk.Helpers;
using System.Runtime.InteropServices;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class Blake2WrapperTests
    {
        private readonly Blake2Wrapper _wrapper;
        private readonly OperatingSystemDeterminator _operatingSystem;

        public Blake2WrapperTests()
        {
            this._wrapper = new Blake2Wrapper();
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void Blake2512Hash()
        {
            string message = "hello world";
            string hash = this._wrapper.Blake2512(message);
            Assert.NotNull(hash);
            Assert.NotEqual(message, hash);
            Assert.Equal(hash, "Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A==");
        }

        [Fact]
        public void Blake2256Hash()
        {
            string message = "hello world";
            string hash = this._wrapper.Blake2256(message);
            Assert.NotNull(hash);
            Assert.NotEqual(message, hash);
            Assert.Equal(hash, "muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws=");
        }

        [Fact]
        public void Blake2512VerifyPass()
        {
            string message = "hello world";
            string messageToVerify = "hello world";
            string hash = this._wrapper.Blake2512(message);
            bool result = this._wrapper.Blake2512Verify(messageToVerify, hash);
            Assert.Equal(result, true);
        }

        [Fact]
        public void Blake2512VerifyAsyncFail()
        {
            string message = "hello world";
            string messageToVerify = "hello worl";
            string hash = this._wrapper.Blake2512(message);
            bool result = this._wrapper.Blake2512Verify(messageToVerify, hash);
            Assert.Equal(result, false);
        }

        [Fact]
        public void Blake2256VerifyPass()
        {
            string message = "hello world";
            string messageToVerify = "hello world";
            string hashPtr = this._wrapper.Blake2256(message);
            bool result = this._wrapper.Blake2256Verify(messageToVerify, hashPtr);
            Assert.Equal(result, true);
        }

        [Fact]
        public void Blake2256VerifyFailAsync()
        {
            string message = "hello world";
            string messageToVerify = "hello worl";
            string hash = this._wrapper.Blake2256(message);
            bool result = this._wrapper.Blake2256Verify(messageToVerify, hash);
            Assert.Equal(result, false);
        }
    }
}