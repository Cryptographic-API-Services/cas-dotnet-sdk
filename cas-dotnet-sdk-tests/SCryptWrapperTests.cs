﻿using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers;
using System.Runtime.InteropServices;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class SCryptWrapperTests
    {
        private readonly SCryptWrapper _scrypt;
        private readonly string _password;
        private readonly OperatingSystemDeterminator _operatingSystem;
        public SCryptWrapperTests()
        {
            this._scrypt = new SCryptWrapper();
            this._password = "TestPasswordToHash";
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void HashPassword()
        {
            string hashedPassword = this._scrypt.HashPassword(this._password);
            Assert.NotNull(hashedPassword);
            Assert.NotEqual(hashedPassword, this._password);
        }

        [Fact]
        public void VerifyPassword()
        {

            string hashedPassword = this._scrypt.HashPassword(this._password);
            bool isValid = this._scrypt.VerifyPassword(this._password, hashedPassword);
            Assert.True(isValid);
        }
    }
}