namespace CasDotnetSdk.Hashers
{
    public enum IHasherType
    {
        SHA = 0,
        Blake2 = 1
    }
    public static class HasherFactory
    {
        public static IHasherBase Get(IHasherType type)
        {
            IHasherBase result = null;
            switch (type)
            {
                case IHasherType.SHA:
                    result = new SHAWrapper();
                    break;
                case IHasherType.Blake2:
                    result = new Blake2Wrapper();
                    break;
            }
            return result;
        }
    }
}
