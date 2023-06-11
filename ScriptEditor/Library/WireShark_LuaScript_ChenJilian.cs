//------------------------------------------------------------------------------
// <auto-generated>
//     此代码由工具生成。
//     运行时版本:4.0.30319.42000
//
//     对此文件的更改可能会导致不正确的行为，并且如果
//     重新生成代码，这些更改将会丢失。
// </auto-generated>
//------------------------------------------------------------------------------

namespace WireShark_LuaScript
{
    using System;
    using System.Data;
    using System.Collections.Generic;
    using DataToolInterface.Format.Config.Global;
    using DataToolInterface.Format.Config.Input;
    using DataToolInterface.Format.Config.Model;
    using DataToolInterface.Format.Config.Output;
    using DataToolInterface.Format.Config;
    using DataToolInterface.Format.File.Binary;
    using DataToolInterface.Format.File.CSharp;
    using DataToolInterface.Format.File.Excel;
    using DataToolInterface.Format.File.Ini;
    using DataToolInterface.Format.File.Lua;
    using DataToolInterface.Format.File.Xml;
    using DataToolInterface.Format.File;
    using DataToolInterface.Format.Script;
    using DataToolInterface.Auxiliary;
    using DefaultConfig;
    
    [DataToolAttribute(project=@"WireShark", name=@"LuaScript", version=@"1.0.0.1", author=@"ChenJilian")]
    public partial class ChenJilian
    {
        public static Global Global = new Global();
        public Input Input;
        public Output Output;
        public ChenJilian()
        {
            Input = new Input();
            Output = new Output();
        }
    }
    public class Global
    {
    }
    [InputAttribute(path=@"D:\System\Desktop\Temp")]
    public class Input
    {
        public Input_InputPath InputPath;
        public Input()
        {
            InputPath = new Input_InputPath();
        }
    }
    [InputPathAttribute()]
    public class Input_InputPath
    {
        [InputFileAttribute(type=@"Single", name=@"", format=@"Xml", path=@"")]
        public InputFile InputFile;
		public Input_InputPath_pathInfo pathInfo { get; set; }

        public Input_InputPath()
        {
            pathInfo = new Input_InputPath_pathInfo();
        }
    }
    public class Input_InputPath_pathInfo
    {
        public Global Global = ChenJilian.Global;
    }
    [XmlFileAttribute(format=@"Xml")]
    public class InputFile
    {
        [XmlElementSingleAttribute(type=@"Single")]
        public WireSharkScript WireSharkScript;
		public InputFile_fileInfo fileInfo { get; set; }

        public InputFile()
        {
            WireSharkScript = new WireSharkScript();
            fileInfo = new InputFile_fileInfo();
        }
    }
    public class WireSharkScript
    {
        [XmlAttributeAttribute()]
        public attribute attribute;
        [XmlElementSingleAttribute(type=@"Single")]
        public Branch Branch;
        [XmlElementMultipleAttribute(type=@"Multiple")]
        public List<Proto> Proto;
        public WireSharkScript()
        {
            attribute = new attribute();
            Branch = new Branch();
            Proto = new List<Proto>();
        }
    }
    public class attribute
    {
        [XmlAttributeAttribute(type=@"String")]
        public String project;
        [XmlAttributeAttribute(type=@"String")]
        public String name;
        [XmlAttributeAttribute(type=@"String")]
        public String version;
        [XmlAttributeAttribute(type=@"String")]
        public String author;
        public attribute()
        {
        }
    }
    public class Branch
    {
        [XmlAttributeAttribute()]
        public attribute_0 attribute;
        [XmlElementDefaultAttribute()]
        public List<XmlDefaultType> elements;
        public Branch()
        {
            attribute = new attribute_0();
            elements = new List<XmlDefaultType>();
        }
    }
    public class attribute_0
    {
        [XmlAttributeAttribute(type=@"UINT16[]")]
        public List<UInt16> port;
        [XmlAttributeAttribute(type=@"String")]
        public String endian;
        public attribute_0()
        {
            port = new List<UInt16>();
        }
    }
    public class XmlDefaultType
    {
        public String name;
        public XmlAttributeDictionary attribute;
        public String content;
        public List<XmlDefaultType> elements;
        public XmlDefaultType()
        {
            attribute = new XmlAttributeDictionary();
            elements = new List<XmlDefaultType>();
        }
    }
    public class Proto
    {
        [XmlAttributeAttribute()]
        public attribute_1 attribute;
        [XmlElementDefaultAttribute()]
        public List<XmlDefaultType> elements;
        public Proto()
        {
            attribute = new attribute_1();
            elements = new List<XmlDefaultType>();
        }
    }
    public class attribute_1
    {
        [XmlAttributeAttribute(type=@"String")]
        public String name;
        [XmlAttributeAttribute(type=@"String")]
        public String endian;
        public attribute_1()
        {
        }
    }
    public class InputFile_fileInfo
    {
        public Global Global = ChenJilian.Global;
    }
    [OutputAttribute(path=@"E:\Wireshark\lua_CJL")]
    public class Output
    {
        public Output_Outputpath Outputpath;
        public Output()
        {
            Outputpath = new Output_Outputpath();
        }
    }
    [OutputPathAttribute(path=@"", describe=@"")]
    public class Output_Outputpath
    {
        [OutputFileAttribute(type=@"Single", name=@"WireShark_LuaScript_{local:project}_{local:name}_{local:version}_{local:author}.lua", format=@"Lua", path=@"", describe=@"")]
        public LuaFile OutputFile;
		public Output_Outputpath_pathInfo pathInfo { get; set; }

        public Output_Outputpath()
        {
            pathInfo = new Output_Outputpath_pathInfo();
        }
    }
    public class Output_Outputpath_pathInfo
    {
        public Global Global = ChenJilian.Global;
    }
    [LuaFileAttribute(format=@"Lua")]
    [System.Xml.Serialization.XmlInclude(typeof(LuaStatement))]
    [System.Xml.Serialization.XmlInclude(typeof(LuaBlock))]
    [System.Xml.Serialization.XmlInclude(typeof(LuaIntentBlock))]
    public class LuaFile
    {
        public List<LuaChunk> body;
		public LuaFile_fileInfo fileInfo { get; set; }

        public LuaFile()
        {
            body = new List<LuaChunk>();
            fileInfo = new LuaFile_fileInfo();
        }
    }
    public abstract class LuaChunk
    {
    }
    public class LuaStatement : LuaChunk
    {
        public String body;
    }
    public class LuaBlock : LuaChunk
    {
        public String head;
        public String tail;
        public List<LuaChunk> body;
        public LuaBlock()
        {
            body = new List<LuaChunk>();
        }
    }
    public class LuaIntentBlock : LuaChunk
    {
        public List<LuaChunk> body;
        public LuaIntentBlock()
        {
            body = new List<LuaChunk>();
        }
    }
    public class LuaFile_fileInfo
    {
        public Global Global = ChenJilian.Global;
        public String project = "project";
        public String name = "name";
        public String version = "version";
        public String author = "author";
    }
}