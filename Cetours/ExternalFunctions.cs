using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

public static unsafe class ExternalFunctions
{
    public static int strcmp(string st1, string st2)
    {
        int iST1 = 0, iST2 = 0;
        for (int i = 0; i < (st1.Length > st2.Length ? st1.Length : st2.Length); i++)
        {
            iST1 += (i >= st1.Length ? 0 : st1[i]) - (i >= st2.Length ? 0 : st2[i]);
            if (iST2 < 0)
            {
                if (iST1 < 0)
                    iST2 += iST1;
                if (iST1 > 0)
                    iST2 += -iST1;
            }
            else
            {
                iST2 += iST1;
            }
        }
        return iST2;
    }

    public static bool fullstrcmp(byte* p1, byte* p2, int length)
    {
        for (int i = 0; i < length; i++)
            if (p1[i] != p2[i])
                return false;
        return true;
    }

    public static void memset(void* dset, byte c, long count)
    {
        var ptr = (byte*)dset;
        for (int i = 0; i < count; i++)
            ptr[i] = c;
    }
}