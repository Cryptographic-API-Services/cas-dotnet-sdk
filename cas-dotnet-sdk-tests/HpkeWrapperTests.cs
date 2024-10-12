using CasDotnetSdk.Hybrid;
using CasDotnetSdk.Hybrid.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace CasDotnetSdkTests
{
    public class HpkeWrapperTests
    {
        private HpkeWrapper _wrapper { get; set; }

        public HpkeWrapperTests()
        {
            this._wrapper = new HpkeWrapper();
        }

        [Fact]
        public void GenerateKeyPair()
        {
            HpkeKeyPairResult result = this._wrapper.GenerateKeyPair();
            Assert.NotNull(result.PublicKey);
            Assert.NotNull(result.PrivateKey);
            Assert.NotEmpty(result.PublicKey);
            Assert.NotEmpty(result.PrivateKey);
        }
    }
}
