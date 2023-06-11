using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using DataToolInterface.Format.Script;
using DataToolInterface.Methods;

namespace WireShark_LuaScript
{
    public partial class ChenJilian
    {
        private const string Offset = "offset";
        private const string LastOffset = "lastOffset";
        private const string FirstFlag = "firstFlag";
        private const string Tvb = "tvb";
        private const string Pinfo = "pinfo";
        private const string Tree = "tree";
        private const string AllProtoDissector = "allProto_dissector";
        private const string MyDissectorTable = "myDissectorTable";
        private const string AllProto = "allProto";
        private const string Result = "result";
        private const string MyProto = "myProto";
        
        [GenerateOutput]
        public void Generate()
        {
            var outputFile = Output.Outputpath.OutputFile.NewInstance();
            Output.Outputpath.OutputFile = outputFile;
            
            var wireSharkScript = Input.InputPath.InputFile.WireSharkScript;
            
            outputFile.fileInfo.project = wireSharkScript.attribute.project.Replace(" ","").Replace("-","_");
            outputFile.fileInfo.name = wireSharkScript.attribute.name.Replace(" ","").Replace("-","_");
            outputFile.fileInfo.version = wireSharkScript.attribute.version.Replace(" ","").Replace("-","_");
            outputFile.fileInfo.author = wireSharkScript.attribute.author.Replace(" ","").Replace("-","_");

            var luaStatement = outputFile.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $"-- project:\t {outputFile.fileInfo.project}";
            luaStatement = outputFile.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $"-- name:\t {outputFile.fileInfo.name}";
            luaStatement = outputFile.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $"-- version:\t {outputFile.fileInfo.version}";
            luaStatement = outputFile.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $"-- author:\t {outputFile.fileInfo.author}";
            
            var doFileBlock = outputFile.body.AddNewInstance<LuaChunk,LuaBlock>();
            doFileBlock.head = "do";
            doFileBlock.tail = "end";

            luaStatement = doFileBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local {AllProtoDissector}";
            
            foreach (var proto in wireSharkScript.Proto)
            {
                luaStatement = doFileBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                luaStatement.body = $@"local {proto.attribute.name}_Init";
            }
            
            luaStatement = doFileBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            var allProtoName = $@"{outputFile.fileInfo.project}_{outputFile.fileInfo.name}_{outputFile.fileInfo.version.Replace('.', '_')}_{outputFile.fileInfo.author}";
            luaStatement.body = $@"local {MyDissectorTable} = DissectorTable.new(""{allProtoName}_Table"")";
            
            luaStatement = doFileBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local {AllProto} = Proto.new(""{allProtoName}"",""{allProtoName} Protocol"")";

            var luaBlock = doFileBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
            luaBlock.head = $@"function {AllProto}.dissector({Tvb},{Pinfo},{Tree})";
            luaBlock.tail = "end";

            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local data_Dissector = Dissector.get(""data"")";
            
            luaBlock = luaBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
            luaBlock.head = $@"if not {AllProtoDissector}({Tvb},{Pinfo},{Tree}) then";
            luaBlock.tail = "end";
            
            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"data_Dissector:call({Tvb}(0):tvb(),{Pinfo},{Tree})";
            
            luaStatement = doFileBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local udp_table = DissectorTable.get(""udp.port"")";

            foreach (var port in wireSharkScript.Branch.attribute.port)
            {
                luaStatement = doFileBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                luaStatement.body = $@"udp_table:add({port},{AllProto})";
            }

            var allProtoDissectorBlock = doFileBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
            allProtoDissectorBlock.head = $@"function {AllProtoDissector}({Tvb},{Pinfo},{Tree})";
            allProtoDissectorBlock.tail = "end";

            luaStatement = allProtoDissectorBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local {Result} = false";

            GenerateBranch(wireSharkScript.Branch.elements,allProtoDissectorBlock.body,wireSharkScript.Branch.attribute.endian);
            
            luaStatement = allProtoDissectorBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"return {Result}";

            foreach (var proto in wireSharkScript.Proto)
            {
                GenerateProto(proto, doFileBlock.body,allProtoName);
            }

            foreach (var proto in wireSharkScript.Proto)
            {
                luaStatement = doFileBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                luaStatement.body = $@"{proto.attribute.name}_Init()";
            }
        }

        private void GenerateBranch(List<XmlDefaultType> paramElements,List<LuaChunk> paramBody,string paramEndian)
        {
            var basicElements = paramElements.Where(p => p.name != "Branch").ToList();
            var minLength = basicElements.GetBlockByteLengthByIndex(0);
            
            var branchBlock = paramBody.AddNewInstance<LuaChunk, LuaBlock>();
            branchBlock.head = $@"if {Tvb}:len() > {minLength} then";
            branchBlock.tail = "end";

            var luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local {Offset} = 0";
                
            foreach (var element in basicElements)
            {
                var type = element.attribute["type"];
                var regex = new Regex(@"(?<=(UINT)|(INT))\d+$");
                if (regex.IsMatch(type))
                {
                    var myEndian = element.attribute.ContainsKey("endian") ? element.attribute["endian"] : paramEndian;
                    switch (regex.Match(type).Value)
                    {
                        case "8":
                            luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {element.name} = {Tvb}({Offset},1)";
                            luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + 1";
                            break;
                        case "16":
                            if (myEndian=="Big")
                            {
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"local {element.name} = {Tvb}({Offset},2):uint()";
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"{Offset} = {Offset} + 2";
                            }
                            else
                            {
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"local {element.name} = {Tvb}({Offset},2):le_uint()";
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"{Offset} = {Offset} + 2";
                            }
                            break;
                        case "32":
                            if (myEndian=="Big")
                            {
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"local {element.name} = {Tvb}({Offset},4):uint()";
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"{Offset} = {Offset} + 4";
                            }
                            else
                            {
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"local {element.name} = {Tvb}({Offset},4):le_uint()";
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"{Offset} = {Offset} + 4";
                            }
                            break;
                        case "64":
                            if (myEndian=="Big")
                            {
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"local {element.name} = {Tvb}({Offset},8):uint()";
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"{Offset} = {Offset} + 8";
                            }
                            else
                            {
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"local {element.name} = {Tvb}({Offset},8):le_uint()";
                                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"{Offset} = {Offset} + 8";
                            }
                            break;
                    }
                }
                regex = new Regex(@"(?<=(UINT)|(INT))\d+(?=\[])");
                if (regex.IsMatch(type))
                {
                    switch (regex.Match(type).Value)
                    {
                        case "8":
                            var ifBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            ifBlock.head = $@"if {Tvb}:len() - {Offset} < ({element.attribute["size"]})*1 then";
                            ifBlock.tail = $@"end";
                            luaStatement = ifBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"return false";
                            
                            luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + ({element.attribute["size"]})*1";

                            if (basicElements.IndexOf(element)!=basicElements.Count-1&&basicElements[basicElements.IndexOf(element)+1].attribute["type"].IsBasicType())
                            {
                                var myBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                                myBlock.head = $@"if {Tvb}:len() - {Offset} < {basicElements.GetBlockByteLengthByIndex(basicElements.IndexOf(element)+1)} then";
                                myBlock.tail = $@"end";
                                luaStatement = myBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"return false";
                            }
                            break;
                        case "16":
                            ifBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            ifBlock.head = $@"if {Tvb}:len() - {Offset} < ({element.attribute["size"]})*2 then";
                            ifBlock.tail = $@"end";
                            luaStatement = ifBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"return false";
                            
                            luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + ({element.attribute["size"]})*2";

                            if (basicElements.IndexOf(element)!=basicElements.Count-1&&basicElements[basicElements.IndexOf(element)+1].attribute["type"].IsBasicType())
                            {
                                var myBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                                myBlock.head = $@"if {Tvb}:len() - {Offset} < {basicElements.GetBlockByteLengthByIndex(basicElements.IndexOf(element)+1)} then";
                                myBlock.tail = $@"end";
                                luaStatement = myBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"return false";
                            }
                            break;
                        case "32":
                            ifBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            ifBlock.head = $@"if {Tvb}:len() - {Offset} < ({element.attribute["size"]})*4 then";
                            ifBlock.tail = $@"end";
                            luaStatement = ifBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"return false";
                            
                            luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + ({element.attribute["size"]})*4";

                            if (basicElements.IndexOf(element)!=basicElements.Count-1&&basicElements[basicElements.IndexOf(element)+1].attribute["type"].IsBasicType())
                            {
                                var myBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                                myBlock.head = $@"if {Tvb}:len() - {Offset} < {basicElements.GetBlockByteLengthByIndex(basicElements.IndexOf(element)+1)} then";
                                myBlock.tail = $@"end";
                                luaStatement = myBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"return false";
                            }
                            break;
                        case "64":
                            ifBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            ifBlock.head = $@"if {Tvb}:len() - {Offset} < ({element.attribute["size"]})*8 then";
                            ifBlock.tail = $@"end";
                            luaStatement = ifBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"return false";
                            
                            luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + ({element.attribute["size"]})*8";

                            if (basicElements.IndexOf(element)!=basicElements.Count-1&&basicElements[basicElements.IndexOf(element)+1].attribute["type"].IsBasicType())
                            {
                                var myBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                                myBlock.head = $@"if {Tvb}:len() - {Offset} < {basicElements.GetBlockByteLengthByIndex(basicElements.IndexOf(element)+1)} then";
                                myBlock.tail = $@"end";
                                luaStatement = myBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body = $@"return false";
                            }
                            break;
                    }
                }
                regex = new Regex(@"(?<=BYTE)\d+");
                if (regex.IsMatch(type))
                {
                    luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{Offset} = {Offset} + {regex.Match(type).Value}";
                }
            }

            var branches = paramElements.Where(p=>p.name=="Branch").ToArray();
            for (var i = 0; i < branches.Length; i++)
            {
                luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                var regex = new Regex($@"(?<=\w+)=(?=\w+)");
                luaStatement.body = $@"{(i==0?"if":"elseif")} {regex.Replace(branches[i].attribute["condition"],"==").Replace("^"," and ").Replace("|"," or ")} then";
                var luaIntentBlock = branchBlock.body.AddNewInstance<LuaChunk, LuaIntentBlock>();
                if (branches[i].attribute.ContainsKey("name"))
                {
                    luaStatement = luaIntentBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{Pinfo}.cols.protocol = ""{branches[i].attribute["name"]}""";
                    luaStatement = luaIntentBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{MyDissectorTable}:get_dissector({(UInt32)branches[i].attribute["name"].GetHashCode()}):call({Tvb},{Pinfo},{Tree})";
                    luaStatement = luaIntentBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{Result} = true";
                }
                else
                {
                    GenerateBranch(branches[i].elements, luaIntentBlock.body,branches[i].attribute.ContainsKey("endian")?branches[i].attribute["endian"]:paramEndian);
                }

                if (i==branches.Length-1)
                {
                    luaStatement = branchBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = "end";
                }
            }
        }

        private void GenerateProto(Proto paramProto,List<LuaChunk> paramBody,string paramProtoPrefix)
        {
            var protoBlock = paramBody.AddNewInstance<LuaChunk, LuaBlock>();
            protoBlock.head = $@"function {paramProto.attribute.name}_Init()";
            protoBlock.tail = "end";
            
            var luaStatement = protoBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local {MyProto} = Proto.new(""{paramProtoPrefix}.{paramProto.attribute.name}"",""{paramProto.attribute.name} Protocol"")";

            GenerateProtoField(paramProto.elements,protoBlock.body,$@"{paramProtoPrefix}.{paramProto.attribute.name}");

            var protoDissectorBlock = protoBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
            protoDissectorBlock.head = $@"function {MyProto}.dissector({Tvb},{Pinfo},{Tree})";
            protoDissectorBlock.tail = "end";
            luaStatement = protoDissectorBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local {Tree} = {Tree}:add({AllProto},{Tvb}())";
            luaStatement = protoDissectorBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local {Tree} = {Tree}:add({MyProto},{Tvb}())";
            luaStatement = protoDissectorBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"local {Offset} = 0";
            
            GenerateProtoDissector(paramProto.elements, protoDissectorBlock.body,$@"{paramProtoPrefix}.{paramProto.attribute.name}",Tree,paramProto.attribute.endian);
            luaStatement = protoBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
            luaStatement.body = $@"myDissectorTable:add({(UInt32)paramProto.attribute.name.GetHashCode()},{MyProto})";
            
        }

        private void GenerateProtoField(List<XmlDefaultType> paramElements,List<LuaChunk> paramBody,string paramPrefix)
        {
            var bitRegex = new Regex($@"(?<=BIT)\d(-\d)?$");
            var basicRegex = new Regex(@"(?<=(UINT)|(INT))\d+$");
            var advancedRegex = new Regex($@"(Single)|(Multiple)");
            var basicMultipleRegex = new Regex(@"(?<=(UINT)|(INT))\d+(?=\[])");
            var byteRegex = new Regex(@"(?<=BYTE)\d+$");

            foreach (var element in paramElements)
            {
                if (bitRegex.IsMatch(element.attribute["type"]))
                {
                    var match = bitRegex.Match(element.attribute["type"]).Value;
                    var bitMask = match.Split('-').Select(byte.Parse).ToArray().GetBitMask();
                    string itemTable = null;
                    if (element.elements.Any())
                    {
                        itemTable = element.elements.ToTable();
                    }

                    var luaStatement = paramBody.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{MyProto}.fields.{$@"{paramPrefix}.{element.name}".Replace('.','_')} = ProtoField.uint8(""{paramPrefix}.{element.name}"",""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"",base.{(element.attribute.ContainsKey("format")?element.attribute["format"]:"DEC")},{(itemTable!=null?itemTable+",":"nil,")}{bitMask})";
                }
                else if (basicRegex.IsMatch(element.attribute["type"]))
                {
                    var match = basicRegex.Match(element.attribute["type"]).Value;
                    if (!element.elements.Any()||element.elements.All(p=>p.name=="Item"))
                    {
                        var itemTable = element.elements.Any()?element.elements.ToTable():null;
                        var luaStatement = paramBody.AddNewInstance<LuaChunk, LuaStatement>();
                        luaStatement.body = $@"{MyProto}.fields.{$@"{paramPrefix}.{element.name}".Replace('.','_')} = ProtoField.uint{match}(""{paramPrefix}.{element.name}"",""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"",base.{(element.attribute.ContainsKey("format")?element.attribute["format"]:"DEC")}{(itemTable!=null?","+itemTable:"")})";
                    }
                    else
                    {
                        foreach (var maskElement in element.elements)
                        {
                            var itemTable = maskElement.elements.Any()?maskElement.elements.ToTable():null;
                            var luaStatement = paramBody.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{MyProto}.fields.{$@"{paramPrefix}.{element.name}.{maskElement.name}".Replace('.','_')} = ProtoField.uint{match}(""{paramPrefix}.{element.name}.{maskElement.name}"",""{(maskElement.attribute.ContainsKey("describe")?maskElement.attribute["describe"]:maskElement.name)}"",base.{(maskElement.attribute.ContainsKey("format")?element.attribute["format"]:"HEX")},{itemTable??"nil"},{maskElement.attribute["mask"]})";
                        }
                    }
                }
                else if (basicMultipleRegex.IsMatch(element.attribute["type"]))
                {
                    var luaStatement = paramBody.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{MyProto}.fields.{$@"{paramPrefix}.{element.name}".Replace('.','_')} = ProtoField.bytes(""{paramPrefix}.{element.name}"",""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"")";
                }
                else if (advancedRegex.IsMatch(element.attribute["type"]))
                {
                    GenerateProtoField(element.elements, paramBody, $@"{paramPrefix}.{element.name}");
                }
                else if (byteRegex.IsMatch(element.attribute["type"]))
                {
                    var luaStatement = paramBody.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{MyProto}.fields.{$@"{paramPrefix}.{element.name}".Replace('.','_')} = ProtoField.bytes(""{paramPrefix}.{element.name}"",""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"")";
                }
            }
        }

        private void GenerateProtoDissector(List<XmlDefaultType> paramElements,List<LuaChunk> paramBody,string paramPrefix,string paramTreeName,string paramEndian)
        {
            var minLength = paramElements.GetBlockByteLengthByIndex(0);
            var ifBlock1 = paramBody.AddNewInstance<LuaChunk, LuaBlock>();
            ifBlock1.head = $@"if {Tvb}:len() - {Offset} >= {minLength} then";
            ifBlock1.tail = "else";
            var ifBlockBody = ifBlock1.body;
                
            var luaBlock1 = paramBody.AddNewInstance<LuaChunk, LuaBlock>();
            luaBlock1.tail = "end";
            var luaStatement = luaBlock1.body.AddNewInstance<LuaChunk,LuaStatement>();
            luaStatement.body = $@"{paramTreeName}:add(""!!!!frame data drop"")";
            luaStatement = luaBlock1.body.AddNewInstance<LuaChunk,LuaStatement>();
            luaStatement.body = $@"return";
            
            var bitRegex = new Regex($@"(?<=BIT)\d(-\d)?$");
            var basicRegex = new Regex(@"(?<=(UINT)|(INT))\d+$");
            var advancedRegex = new Regex($@"(Single)|(Multiple)");
            var reserveRegex = new Regex($@"(?<=BYTE)\d+$");
            var basicMultipleRegex = new Regex(@"(?<=(UINT)|(INT))\d+(?=\[])");

            foreach (var element in paramElements)
            {
                var myEndian = element.attribute.ContainsKey("endian")
                    ? element.attribute["endian"]
                    : paramEndian;
                
                var fieldName = $@"{paramPrefix}.{element.name}".Replace('.', '_');
                
                var conditionBlockBody = ifBlockBody;
                if (element.attribute.ContainsKey("condition"))
                {
                    var conditionBlock = ifBlockBody.AddNewInstance<LuaChunk, LuaBlock>();
                    var regex = new Regex($@"(?<=\w+)=(?=\w+)");
                    conditionBlock.head = $@"if {regex.Replace($@"{paramPrefix.Replace('.', '_')}_"+element.attribute["condition"],"==")} then";
                    conditionBlock.tail = $@"end";

                    if (element.attribute["type"].GetByteMaxLength()>0)
                    {
                        var block = conditionBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                        block.head = $@"if {Tvb}:len() - {Offset} < {element.attribute["type"].GetByteMaxLength()} then";
                        block.tail = $@"end";
                        luaStatement = block.body.AddNewInstance<LuaChunk, LuaStatement>();
                        luaStatement.body = $@"{paramTreeName}:add(""!!!!frame data drop"")";
                        luaStatement = block.body.AddNewInstance<LuaChunk,LuaStatement>();
                        luaStatement.body = $@"return";
                    }

                    if (paramElements.IndexOf(element)!=paramElements.Count-1&&paramElements[paramElements.IndexOf(element)+1].attribute["type"].IsBasicType()&&!paramElements[paramElements.IndexOf(element)+1].attribute.ContainsKey("condition"))
                    {
                        var checkFlowBlock = ifBlockBody.AddNewInstance<LuaChunk, LuaBlock>();
                        checkFlowBlock.head = $@"if {Tvb}:len() - {Offset} < {paramElements.GetBlockByteLengthByIndex(paramElements.IndexOf(element)+1)} then";
                        checkFlowBlock.tail = $@"end";
                        luaStatement = checkFlowBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                        luaStatement.body = $@"{paramTreeName}:add(""!!!!frame data drop"")";
                        luaStatement = checkFlowBlock.body.AddNewInstance<LuaChunk,LuaStatement>();
                        luaStatement.body = $@"return";
                    }
                    
                    
                    conditionBlockBody = conditionBlock.body;
                }
                
                if (bitRegex.IsMatch(element.attribute["type"]))
                {
                    var match = bitRegex.Match(element.attribute["type"]).Value;
                    var bitMask = match.Split('-').Select(byte.Parse).ToArray();
                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{paramTreeName}:add({MyProto}.fields.{fieldName}, {Tvb}({Offset}, 1))";
                    if (bitMask.Last()==7)
                    {
                        luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                        luaStatement.body = $@"{Offset} = {Offset} + 1";
                    }

                }
                else if (basicRegex.IsMatch(element.attribute["type"]))
                {
                    var match = basicRegex.Match(element.attribute["type"]).Value;
                    switch (match)
                    {
                        case "8":
                            if (element.elements.Any() && element.elements.All(p => p.name != "Item"))
                            {
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"local {paramTreeName}_{element.name} = {paramTreeName}:add(""{(element.attribute.ContainsKey("describe") ? element.attribute["describe"] : element.name)}"")";
                                foreach (var subElement in element.elements)
                                {
                                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                    luaStatement.body =
                                        $@"{paramTreeName}_{element.name}:add_packet_field({MyProto}.fields.{fieldName}_{subElement.name}, {Tvb}({Offset}, 1),{(myEndian == "Big" ? "ENC_BIG_ENDIAN" : "ENC_LITTLE_ENDIAN")})";
                                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                    luaStatement.body =
                                        $@"local {fieldName}_{subElement.name} = {Tvb}({Offset}, 1):{(myEndian == "Big" ? "uint()" : "le_uint()")}";
                                }
                            }
                            else
                            {
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"{paramTreeName}:add_packet_field({MyProto}.fields.{fieldName}, {Tvb}({Offset}, 1),{(myEndian == "Big" ? "ENC_BIG_ENDIAN" : "ENC_LITTLE_ENDIAN")})";
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"local {fieldName} = {Tvb}({Offset}, 1):{(myEndian == "Big" ? "uint()" : "le_uint()")}";
                            }

                            luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + 1";
                            break;
                        case "16":
                            if (element.elements.Any() && element.elements.All(p => p.name != "Item"))
                            {
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"local {paramTreeName}_{element.name} = {paramTreeName}:add(""{(element.attribute.ContainsKey("describe") ? element.attribute["describe"] : element.name)}"")";
                                foreach (var subElement in element.elements)
                                {
                                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                    luaStatement.body =
                                        $@"{paramTreeName}_{element.name}:add_packet_field({MyProto}.fields.{fieldName}_{subElement.name}, {Tvb}({Offset}, 2),{(myEndian == "Big" ? "ENC_BIG_ENDIAN" : "ENC_LITTLE_ENDIAN")})";
                                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                    luaStatement.body =
                                        $@"local {fieldName}_{subElement.name} = {Tvb}({Offset}, 2):{(myEndian == "Big" ? "uint()" : "le_uint()")}";
                                }
                            }
                            else
                            {
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"{paramTreeName}:add_packet_field({MyProto}.fields.{fieldName}, {Tvb}({Offset}, 2),{(myEndian == "Big" ? "ENC_BIG_ENDIAN" : "ENC_LITTLE_ENDIAN")})";
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"local {fieldName} = {Tvb}({Offset}, 2):{(myEndian == "Big" ? "uint()" : "le_uint()")}";
                            }

                            luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + 2";
                            break;
                        case "32":
                            if (element.elements.Any() && element.elements.All(p => p.name != "Item"))
                            {
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"local {paramTreeName}_{element.name} = {paramTreeName}:add(""{(element.attribute.ContainsKey("describe") ? element.attribute["describe"] : element.name)}"")";
                                foreach (var subElement in element.elements)
                                {
                                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                    luaStatement.body =
                                        $@"{paramTreeName}_{element.name}:add_packet_field({MyProto}.fields.{fieldName}_{subElement.name}, {Tvb}({Offset}, 4),{(myEndian == "Big" ? "ENC_BIG_ENDIAN" : "ENC_LITTLE_ENDIAN")})";
                                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                    luaStatement.body =
                                        $@"local {fieldName}_{subElement.name} = {Tvb}({Offset}, 4):{(myEndian == "Big" ? "uint()" : "le_uint()")}";
                                }
                            }
                            else
                            {
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"{paramTreeName}:add_packet_field({MyProto}.fields.{fieldName}, {Tvb}({Offset}, 4),{(myEndian == "Big" ? "ENC_BIG_ENDIAN" : "ENC_LITTLE_ENDIAN")})";
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"local {fieldName} = {Tvb}({Offset}, 4):{(myEndian == "Big" ? "uint()" : "le_uint()")}";
                            }

                            luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + 4";
                            break;
                        case "64":
                            if (element.elements.Any() && element.elements.All(p => p.name != "Item"))
                            {
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"local {paramTreeName}_{element.name} = {paramTreeName}:add(""{(element.attribute.ContainsKey("describe") ? element.attribute["describe"] : element.name)}"")";
                                foreach (var subElement in element.elements)
                                {
                                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                    luaStatement.body =
                                        $@"{paramTreeName}_{element.name}:add_packet_field({MyProto}.fields.{fieldName}_{subElement.name}, {Tvb}({Offset}, 8),{(myEndian == "Big" ? "ENC_BIG_ENDIAN" : "ENC_LITTLE_ENDIAN")})";
                                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                    luaStatement.body =
                                        $@"local {fieldName}_{subElement.name} = {Tvb}({Offset}, 8):{(myEndian == "Big" ? "uint()" : "le_uint()")}";
                                }
                            }
                            else
                            {
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"{paramTreeName}:add_packet_field({MyProto}.fields.{fieldName}, {Tvb}({Offset}, 8),{(myEndian == "Big" ? "ENC_BIG_ENDIAN" : "ENC_LITTLE_ENDIAN")})";
                                luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                                luaStatement.body =
                                    $@"local {fieldName} = {Tvb}({Offset}, 8):{(myEndian == "Big" ? "uint()" : "le_uint()")}";
                            }

                            luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + 8";
                            break;
                    }
                }
                else if (basicMultipleRegex.IsMatch(element.attribute["type"]))
                {
                    var match = basicMultipleRegex.Match(element.attribute["type"]).Value;
                    var type = int.Parse(match);
                    
                    var ifBlock = conditionBlockBody.AddNewInstance<LuaChunk, LuaBlock>();
                    ifBlock.head = $@"if {Tvb}:len() - {Offset} < ({paramPrefix.Replace('.','_')}_{element.attribute["size"]})*{type/8} then";
                    ifBlock.tail = "end";
                    
                    luaStatement = ifBlock.body.AddNewInstance<LuaChunk,LuaStatement>();
                    luaStatement.body = $@"{paramTreeName}:add(""!!!!frame data drop"")";
                    luaStatement = ifBlock.body.AddNewInstance<LuaChunk,LuaStatement>();
                    luaStatement.body = $@"return";
                    
                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"local {paramTreeName}_{element.name} = {paramTreeName}:add({MyProto}.fields.{fieldName}, {Tvb}({Offset}, ({paramPrefix.Replace('.','_')}_{element.attribute["size"]})*{type/8}))";

                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{Offset} = {Offset} + ({paramPrefix.Replace('.','_')}_{element.attribute["size"]})*{type/8}";
                    
                    if (paramElements.IndexOf(element)!=paramElements.Count-1&&paramElements[paramElements.IndexOf(element)+1].attribute["type"].IsBasicType()&&!paramElements[paramElements.IndexOf(element)+1].attribute.ContainsKey("condition"))
                    {
                        minLength = paramElements.GetBlockByteLengthByIndex(paramElements.IndexOf(element)+1);
                        ifBlock = conditionBlockBody.AddNewInstance<LuaChunk, LuaBlock>();
                        ifBlock.head = $@"if {Tvb}:len() - {Offset} < {minLength} then";
                        ifBlock.tail = "end";
                
                        luaStatement = ifBlock.body.AddNewInstance<LuaChunk,LuaStatement>();
                        luaStatement.body = $@"{paramTreeName}:add(""!!!!frame data drop"")";
                        luaStatement = ifBlock.body.AddNewInstance<LuaChunk,LuaStatement>();
                        luaStatement.body = $@"return";
                    }
                }
                else if (advancedRegex.IsMatch(element.attribute["type"]))
                {
                    var match = advancedRegex.Match(element.attribute["type"]).Value;
                    if (match == "Single")
                    {
                        var subTreeName = $@"{Tree}_{paramTreeName + "_" + element.name}";
                        luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                        luaStatement.body = $@"local {subTreeName} = {paramTreeName}:add(""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"")";
                        GenerateProtoDissector(element.elements,conditionBlockBody,$@"{paramPrefix}.{element.name}",subTreeName,myEndian);
                    }
                    else
                    {
                        if (element.attribute.ContainsKey("length"))
                        {
                            var luaBlock = conditionBlockBody.AddNewInstance<LuaChunk, LuaBlock>();
                            luaBlock.head = $@"if ({$@"{paramPrefix}.{element.attribute["length"]}".Replace('.','_')}) > 0 then";
                            luaBlock.tail = "end";
                            
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {paramTreeName}_{element.name} = {paramTreeName}:add(""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"")";
                            
                            var tvbCheckBlock = luaBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            tvbCheckBlock.head = $@"if {Tvb}:len() - {Offset} < {$@"{paramPrefix}.{element.attribute["length"]}".Replace('.','_')} then";
                            tvbCheckBlock.tail = $@"end";
                            luaStatement = tvbCheckBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{paramTreeName}_{element.name}:add(""!!!!length not enough"")";
                            luaStatement = tvbCheckBlock.body.AddNewInstance<LuaChunk,LuaStatement>();
                            luaStatement.body = $@"return";
                            
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {Tvb} = {Tvb}:range({Offset},({$@"{paramPrefix}.{element.attribute["length"]}".Replace('.','_')})):tvb()";
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{Offset} = {Offset} + ({$@"{paramPrefix}.{element.attribute["length"]}".Replace('.','_')})";
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {Offset} = 0";
                            var index = ExtendMethod.GetUniqueIndex();
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {index} = 0";
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {LastOffset} = {Offset}";
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {FirstFlag} = 0";
                            
                            luaBlock = luaBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            luaBlock.head = $@"while {Offset} < ({$@"{paramPrefix}.{element.attribute["length"]}".Replace('.','_')}) do";
                            luaBlock.tail = "end";
                            
                            var checkBlock = luaBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            checkBlock.head = $@"if {Offset}=={LastOffset} then";
                            checkBlock.tail = $@"end";
                            var block = checkBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            block.head = $@"if {Offset}==0 and {FirstFlag}==0 then";
                            block.tail = $@"else";
                            luaStatement = block.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{FirstFlag} = 1";
                            block = checkBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            block.tail = $@"end";
                            luaStatement = block.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{paramTreeName}_{element.name}:add(""!!!!no match condition"")";
                            luaStatement = block.body.AddNewInstance<LuaChunk,LuaStatement>();
                            luaStatement.body = $@"return";
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{LastOffset} = {Offset}";

                            var subTreeName = $@"{Tree}_{paramTreeName}_{element.name}_{index}";
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"{index} = {index} + 1";
                            
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {subTreeName} = {paramTreeName}_{element.name}:add(""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"" .. {index})";
                            GenerateProtoDissector(element.elements,luaBlock.body,$@"{paramPrefix}.{element.name}",subTreeName,myEndian);
                        }
                        else
                        {
                            var luaBlock = conditionBlockBody.AddNewInstance<LuaChunk, LuaBlock>();
                            luaBlock.head = $@"if ({$@"{paramPrefix}.{element.attribute["size"]}".Replace('.','_')}) > 0 then";
                            luaBlock.tail = "end";
                        
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {paramTreeName}_{element.name} = {paramTreeName}:add(""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"")";
                        
                            luaBlock = luaBlock.body.AddNewInstance<LuaChunk, LuaBlock>();
                            var index = ExtendMethod.GetUniqueIndex();
                            luaBlock.head = $@"for {index} = 1, ({$@"{paramPrefix}.{element.attribute["size"]}".Replace('.','_')}) do";
                            luaBlock.tail = "end";
                        
                            var subTreeName = $@"{Tree}_{paramTreeName}_{element.name}_{index}";
                            luaStatement = luaBlock.body.AddNewInstance<LuaChunk, LuaStatement>();
                            luaStatement.body = $@"local {subTreeName} = {paramTreeName}_{element.name}:add(""{(element.attribute.ContainsKey("describe")?element.attribute["describe"]:element.name)}"" .. {index})";
                            GenerateProtoDissector(element.elements,luaBlock.body,$@"{paramPrefix}.{element.name}",subTreeName,myEndian);
                        }
                    }
                    if (paramElements.IndexOf(element)!=paramElements.Count-1&&paramElements[paramElements.IndexOf(element)+1].attribute["type"].IsBasicType()&&!paramElements[paramElements.IndexOf(element)+1].attribute.ContainsKey("condition"))
                    {
                        minLength = paramElements.GetBlockByteLengthByIndex(paramElements.IndexOf(element)+1);
                        var ifBlock = conditionBlockBody.AddNewInstance<LuaChunk, LuaBlock>();
                        ifBlock.head = $@"if {Tvb}:len() - {Offset} < {minLength} then";
                        ifBlock.tail = "end";
                
                        luaStatement = ifBlock.body.AddNewInstance<LuaChunk,LuaStatement>();
                        luaStatement.body = $@"{paramTreeName}:add(""!!!!frame data drop"")";
                        luaStatement = ifBlock.body.AddNewInstance<LuaChunk,LuaStatement>();
                        luaStatement.body = $@"return";
                    }
                }
                else if (reserveRegex.IsMatch(element.attribute["type"]))
                {
                    var match = reserveRegex.Match(element.attribute["type"]).Value;
                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"local {paramTreeName}_{element.name} = {paramTreeName}:add({MyProto}.fields.{fieldName}, {Tvb}({Offset},{match}))";
                    luaStatement = conditionBlockBody.AddNewInstance<LuaChunk, LuaStatement>();
                    luaStatement.body = $@"{Offset} = {Offset} + {match}";
                }
            }
        }
    }
}
