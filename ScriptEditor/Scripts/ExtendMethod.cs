using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace WireShark_LuaScript
{
    public static class ExtendMethod
    {
        private static int _indexCount;
        
        private static readonly Regex UintRegex = new Regex(@"(?<=(UINT)|(INT))\d+$");
        private static readonly Regex ByteRegex = new Regex(@"(?<=BYTE)\d+$");
        private static readonly Regex BitRegex = new Regex(@"(?<=BIT)\d(-\d)?$");

        private static int GetByteLength(this string param)
        {
            var length = 0;
            if (UintRegex.IsMatch(param.ToUpper()))
            {
                length = int.Parse(UintRegex.Match(param.ToUpper()).Value)/8;
            }
            else if (ByteRegex.IsMatch(param.ToUpper()))
            {
                length = int.Parse(ByteRegex.Match(param.ToUpper()).Value);
            }
            else if (BitRegex.IsMatch(param.ToUpper()))
            {
                if (BitRegex.Match(param.ToUpper()).Value.Contains('7'))
                {
                    length = 1;
                }
            }

            return length;
        }
        
        public static int GetByteMaxLength(this string param)
        {
            var length = 0;
            var regex1 = UintRegex;
            var regex2 = ByteRegex;
            var regex3 = BitRegex;
            if (regex1.IsMatch(param.ToUpper()))
            {
                length = int.Parse(regex1.Match(param.ToUpper()).Value)/8;
            }
            else if (regex2.IsMatch(param.ToUpper()))
            {
                length = int.Parse(regex2.Match(param.ToUpper()).Value);
            }
            else if (regex3.IsMatch(param.ToUpper()))
            {
                length = 1;
            }

            return length;
        }

        public static bool IsBasicType(this string param)
        {
            var result = false;
            var regex1 = UintRegex;
            var regex2 = ByteRegex;
            var regex3 = BitRegex;
            if (regex1.IsMatch(param.ToUpper())||regex2.IsMatch(param.ToUpper())||regex3.IsMatch(param.ToUpper()))
            {
                result = true;
            }

            return result;
        }

        public static int GetBlockByteLengthByIndex(this List<XmlDefaultType> paramElements,int paramIndex)
        {
            var length = 0;
            for (var i = paramIndex; i < paramElements.Count; i++)
            {
                if (paramElements[i].attribute["type"].IsBasicType()&&!paramElements[i].attribute.ContainsKey("condition"))
                {
                    length += paramElements[i].attribute["type"].GetByteLength();
                }
                else
                {
                    break;
                }
            }

            return length;
        }
        
        public static string GetBitMask(this byte[] paramBits)
        {
            byte mask = 0;
            if (paramBits.Length==1)
            {
                mask |= (byte)(1 << paramBits.First());
            }
            else if (paramBits.Length==2)
            {
                for (int i = paramBits[0]; i <= paramBits[1]; i++)
                {
                    mask |= (byte)(1 << i);
                }
            }

            return $@"0x{mask:X2}";
        }

        public static string ToTable(this List<XmlDefaultType> paramElements)
        {
            var stringBuilder = new StringBuilder();
            stringBuilder.Append("{");
            foreach (var element in paramElements)
            {
                stringBuilder.Append($@"[{element.attribute["key"]}] = ""{element.attribute["value"]}"",");
            }

            return $@"{stringBuilder.ToString().TrimEnd(',')}}}";
        }

        public static string GetUniqueIndex()
        {
            return $@"index_{_indexCount++}";
        }
    }
}