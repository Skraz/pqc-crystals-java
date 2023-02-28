package crypto.pqc.kyber;

public class Ntt
{

    /* Code to generate zetas and zetas_inv used in the number-theoretic transform:

    int KYBER_ROOT_OF_UNITY = 17;
    int KYBER_Q = 3329;

    short[] zetas = new short[128];
    short[] zetas_inv = new short[128];

    short[] tree = new short[]{
            0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
                    4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
                    2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
                    6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
                    1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
                    5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
                    3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
                    7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127
        };
        int i, j, k;
        short[] tmp = new short[128];

        int PLANTARD = 1353; // 2 ^ 32 mod q
        int MONT = 2285 // 2 ^ 16 mod q


        tmp[0] = (short) PLANTARD;
        for(i = 1; i < 128; ++i)
            tmp[i] = Ntt.factorQMulMont(tmp[i-1], (short) ((KYBER_ROOT_OF_UNITY*PLANTARD) % KYBER_Q));

        for(i = 0; i < 128; ++i)
            zetas[i] = tmp[tree[i]];

        k = 0;
        for(i = 64; i >= 1; i >>= 1)
            for(j = i; j < 2*i; ++j)
                zetas_inv[k++] = (short) ((-1) * tmp[128 - tree[j]]);

        zetas_inv[127] = (short) (PLANTARD * (PLANTARD * (KYBER_Q - 1) * ((KYBER_Q - 1)/128) % KYBER_Q) % KYBER_Q);
        System.out.printf("Zetas = [");
        for (i = 0; i < 128; i++) {
            System.out.printf("%d, ", (zetas[i] + KYBER_Q) % KYBER_Q);
        }
        System.out.print("]\n");

    System.out.printf("Zetas Inv = [");
        for (i = 0; i < 128; i++) {
            System.out.printf("%d, ", (zetas_inv[i] + KYBER_Q) % KYBER_Q);
        }
        System.out.print("]\n");

    */

    // Plantard NTT Zetas
    
    // public static final short[] nttZetas = new short[] {
    //     1353, 2970, 627, 402, 1027, 2092, 2587, 2025, 1005, 501, 2658, 3074, 69, 
    //     1207, 2955, 2914, 2488, 3188, 747, 909, 459, 358, 1999, 1871, 608, 1903, 
    //     2880, 2181, 3013, 1661, 2533, 2962, 1321, 2169, 125, 112, 518, 2355, 1052, 
    //     117, 280, 1183, 2728, 873, 1957, 1860, 2612, 50, 3310, 1501, 3239, 452, 426, 
    //     2965, 441, 1780, 1130, 613, 1498, 1502, 1121, 1324, 1981, 3293, 2362, 3155, 
    //     851, 2680, 2408, 2850, 2821, 184, 42, 11, 1075, 1629, 460, 279, 3055, 1672, 
    //     2161, 2389, 1651, 2731, 3060, 1277, 2230, 267, 1834, 1590, 2555, 1224, 2332, 
    //     2196, 2461, 1992, 1039, 1144, 1943, 2966, 1234, 2384, 1465, 780, 757, 119, 
    //     432, 2491, 1950, 2413, 1878, 1443, 983, 2239, 2729, 794, 2840, 2012, 2940, 
    //     770, 1985, 2977, 2219, 1136, 1925, 1059, 2110, 3089};

    // public static final short[] nttZetasInv = new short[]{
    //     1487, 2294, 2887, 1877, 715, 2153, 1968, 2895, 318, 2792, 2733, 1823, 3314, 
    //     2632, 2729, 2081, 916, 840, 21, 310, 2218, 86, 2166, 111, 1913, 1449, 3282, 
    //     1367, 2328, 2978, 3237, 2605, 1733, 3072, 2740, 3036, 1834, 1551, 122, 2118, 
    //     243, 2636, 3062, 2241, 334, 1760, 44, 491, 2019, 1270, 864, 865, 2323, 1636, 
    //     3037, 2189, 237, 3023, 2822, 1076, 2093, 3155, 495, 3027, 500, 1040, 26, 
    //     1652, 2112, 265, 1255, 613, 2527, 1794, 1210, 1851, 980, 41, 2581, 1640, 
    //     2296, 1713, 1957, 1940, 457, 2149, 1635, 2735, 2629, 1873, 1961, 1682, 1038, 
    //     2958, 1572, 1805, 1073, 2365, 2972, 1388, 2242, 1867, 3126, 1442, 769, 1999, 
    //     799, 64, 372, 2638, 1564, 2321, 1252, 2471, 145, 2299, 255, 1862, 213, 1242, 
    //     1161, 18, 3163, 720, 856, 1381, 950, 2208};


    // Montgomery NTTs

    public static final short[] nttZetas = new short[]{
        2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
        2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
        732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
        1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
        107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
        430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
        1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
        418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
        1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
        478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628};

    public static final short[] nttZetasInv = new short[]{
        1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
        1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
        1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
        1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
        3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
        1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
        1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
        2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
        829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
        3127, 3042, 1907, 1836, 1517, 359, 758, 1441};

    /**
     * NTT
     * Inplace number-theoretic transform (NTT) in Rq
     * input is in standard order, output is in bitreversed order
     * @param inp Array of Short: Standard Polynomial Values
     * @return Array of Short: Bit Reversed Polynomial Values
     */
    public static short[] ntt(short[] inp)
    {
        short[] r = new short[KyberEngine.KyberN];
        System.arraycopy(inp, 0, r, 0, r.length);
        int len, start, j, k;
        short t, zeta;

        k = 1;
        for (len = 128; len >= 2; len >>= 1)
        {
            for (start = 0; start < 256; start = j + len)
            {
                zeta = nttZetas[k++];
                for (j = start; j < start + len; ++j)
                {
                    t = factorQMulMont(zeta, r[j + len]);
                    r[j + len] = (short)(r[j] - t);
                    r[j] = (short)(r[j] + t);
                }
            }
        }
        return r;
    }

    

    /**
     * Inverse NTT
     * Inplace inverse number-theoretic transform in Rq and
     * multiplication by Montgomery factor 2^16.
     * @param inp
     * @return
     */
    public static short[] invNtt(short[] inp)
    {
        short[] r = new short[KyberEngine.KyberN];
        System.arraycopy(inp, 0, r, 0, KyberEngine.KyberN);
        int len, start, j, k;
        short t, zeta;
        k = 0;
        for (len = 2; len <= 128; len <<= 1)
        {
            for (start = 0; start < 256; start = j + len)
            {
                zeta = nttZetasInv[k++];
                for (j = start; j < start + len; ++j)
                {
                    t = r[j];
                    r[j] = Reduce.barretReduce((short)(t + r[j + len]));
                    r[j + len] = (short)(t - r[j + len]);
                    r[j + len] = factorQMulMont(zeta, r[j + len]);

                }
            }
        }


        // Multiply Inverse NTT by MONT
        for (j = 0; j < 256; ++j)
        {
            r[j] = factorQMulMont(r[j], Ntt.nttZetasInv[127]);
        }
        return r;
    }

    /**
     * Factor Q Multiplication Montgomery
     * Multiplication followed by Montgomery reduction
     * @param a
     * @param b
     * @return
     */
    public static short factorQMulMont(short a, short b)
    {
        // System.out.printf("a = %d, b = %d\n", a, b);
        int d = a * b;
        // System.out.printf("Montgomery = %d, Plantard = %d\n\n", Reduce.montgomeryReduce((short)(a * b)), Reduce.plantardReduce(d));
        // return Reduce.plantardReduce(d);
        return Reduce.montgomeryReduce(d);
    }

    /**
     * Base Multiplication / Butterfly
     * Multiplication of polynomials in Zq[X]/(X^2-zeta)
     * used for multiplication of elements in Rq in NTT domain
     * @param outPoly 
     * @param outIndex
     * @param a0
     * @param a1
     * @param b0
     * @param b1
     * @param zeta
     */
    public static void baseMult(Poly outPoly, int outIndex, short a0, short a1, short b0, short b1, short zeta)
    {
        short outVal0 = factorQMulMont(a1, b1);
        outVal0 = factorQMulMont(outVal0, zeta);
        outVal0 += factorQMulMont(a0, b0);
        outPoly.setCoeffIndex(outIndex, outVal0);

        short outVal1 = factorQMulMont(a0, b1);
        outVal1 += factorQMulMont(a1, b0);
        outPoly.setCoeffIndex(outIndex + 1, outVal1);
    }
}