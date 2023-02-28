package crypto.pqc.kyber;

public class Helper
{
    public static void printByteArray(byte[] bytes)
    {
        for (byte b : bytes)
        {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        System.out.print("\n");
    }

    public static void printShortArray(short[] shorts)
    {
        System.out.print("[");
        for (short s : shorts)
        {
            System.out.printf("%d, ", s);
        }
        System.out.print("]");
    }

    public static void printPolyVec(PolyVec a, int k)
    {
        System.out.print("[");
        for (int i = 0; i < k; i++)
        {
            System.out.printf("%d [", i);
            for (int j = 0; j < KyberEngine.KyberN; j++)
            {
                System.out.print(a.getVectorIndex(i).getCoeffIndex(j) + ", ");
            }
            System.out.println("],");
        }
        System.out.println("]");
    }
}
