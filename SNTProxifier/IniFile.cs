using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Drawing;

namespace SiretT {
    public class IniKey : List<Property> {
        string name;
        public IniKey() { }
        public IniKey(string name) { this.name = name; }
        public Property this[string property] {
            get {
                foreach (Property i in this)
                    if (i.Key.ToLower() == property.ToLower())
                        return i;
                return null;
            }
        }
        public List<Property> Properties { get { return this; } }
        public Property FindProperty(string property) {
            foreach (var i in this)
                if (i.Key.ToLower() == property.ToLower())
                    return i;
            return null;
        }
        public string Name { get { return name; } }
        public override string ToString() {
            return Name;
        }
    }

    public class Property {
        string key; object value;
        public Property() { }
        public Property(string key, object value) {
            this.key = key; this.value = value;
        }
        public string Key { get { return key; } }
        public object Value { get { return value; } set { this.value = value; } }
        public override string ToString() {
            return Key;
        }
    }

    public class IniFile {
        private string file;
        private List<IniKey> keys;
        private Stream fs;

        public IniFile(string filename) {
            Filename = filename;
            Load(filename);
        }

        private void Load(string filename) {
            fs = new FileStream(filename, FileMode.OpenOrCreate, FileAccess.ReadWrite);
            this.file = filename;

            keys = new List<IniKey>();

            using (StreamReader sr = new StreamReader(fs)) {
                string key = "";
                while (!sr.EndOfStream) {
                    var line = sr.ReadLine();
                    string property = "";
                    string value;
                    if (!String.IsNullOrEmpty(line)) {
                        while (line[0] == ' ') line = line.Remove(0, 1);
                        while (line[line.Length - 1] == ' ') line = line.Remove(line.Length - 1, 1);
                        if (Regex.IsMatch(line, @"^\[[_a-z][a-z0-9_]+\]$", RegexOptions.IgnoreCase)) {
                            key = line.Substring(1, line.Length - 2);
                            keys.Add(new IniKey(key));
                        } else if (Regex.IsMatch(line, "^[_a-z][a-z0-9_]+([ ]|)+=([ ]|)+.+$", RegexOptions.IgnoreCase)) {
                            property = Regex.Match(line, "^[_a-z][a-z0-9_]+", RegexOptions.IgnoreCase).Value;
                            int indx = Regex.Match(line, "([ ]|)=([ ]|)").Index;
                            int length = Regex.Match(line, "([ ]|)=([ ]|)").Length;
                            value = line.Substring(indx + length);
                            //double
                            if (Regex.IsMatch(value, @"^([0-9]+\.[0-9]+)$")) {
                                keys[keys.Count - 1].Properties.Add(new Property(property, Double.Parse(value)));
                            }
                            //int
                            else if (Regex.IsMatch(value, "^([0-9]+)$")) {
                                keys[keys.Count - 1].Properties.Add(new Property(property, Int32.Parse(value)));
                            }
                            //Point
                            else if (Regex.IsMatch(value, @"^([0-9]+(\.|)[0-9]+;[0-9]+(\.|)[0-9]+)$")) {
                                value = value.Replace(',', '.').Replace(';', ',');
                                var v1 = double.Parse(value.Substring(0, value.IndexOf(';')));
                                var v2 = double.Parse(value.Substring(value.IndexOf(';') + 1));
                                var point = new System.Drawing.Point((int)v1, (int)v2);
                                keys[keys.Count - 1].Properties.Add(new Property(property, point));
                            }
                            //bool
                            else if (Regex.IsMatch(value, @"(true|false)", RegexOptions.IgnoreCase)) {
                                keys[keys.Count - 1].Properties.Add(new Property(property, Boolean.Parse(value)));
                            }
                            //string
                            else {
                                keys[keys.Count - 1].Properties.Add(new Property(property, value));
                            }
                        }
                    }
                    //if (String.IsNullOrEmpty(line)) {
                    //    key = null; continue;
                    //} else if (line[0] == '[' && line[line.Length - 1] == ']') {
                    //    key = line.Substring(1, line.Length - 2);
                    //    keys.Add(new IniKey(key));
                    //} else if (Regex.Match(line, "[_a-z][a-z0-9_]+").Captures.Count == 1) {
                    //    var indx = line.IndexOf("=");
                    //    property = line.Substring(0, indx);
                    //    value = line.Substring(indx + 1);
                    //    int valueInt = 0; double valueDouble = 0; bool valueBool;
                    //    if (int.TryParse(value, out valueInt))
                    //        keys[keys.Count - 1].Properties.Add(new Property(property, valueInt));
                    //    else if (double.TryParse(value, out valueDouble))
                    //        keys[keys.Count - 1].Properties.Add(new Property(property, valueDouble));
                    //    else if (value.Contains(";") && value.IndexOf(";") == value.LastIndexOf(";")) {
                    //        var x = Convert.ToDouble(value.Substring(0, value.IndexOf(";")));
                    //        var y = Convert.ToDouble(value.Substring(value.IndexOf(";") + 1));
                    //        keys[keys.Count - 1].Properties.Add(new Property(property, new System.Windows.Point((int)x, (int)y)));
                    //    } else if (bool.TryParse(value, out valueBool))
                    //        keys[keys.Count - 1].Properties.Add(new Property(property, valueBool));
                    //    else keys[keys.Count - 1].Properties.Add(new Property(property, value));
                    //}
                }
                sr.Close();
            }
        }

        public List<IniKey> Keys { get { return keys; } }

        public string Filename { get; private set; }

        public IniKey this[string name] {
            get {
                foreach (var i in keys)
                    if (i.Name == name) return i;
                return null;
            }
        }

        public bool Contains(string path) {
            if (path.ToLower().Contains("\\") && path.ToLower().IndexOf("\\") == path.ToLower().LastIndexOf("\\")) {
                var name = path.Substring(0, path.IndexOf("\\"));
                var property = path.Substring(path.IndexOf("\\") + 1);
                foreach (var i in keys) {
                    if (i.Name.ToLower() == name.ToLower() && i[property.ToLower()] != null)
                        return true;
                }
            } else {
                var name = path.Replace("\\", "");
                foreach (var i in keys) {
                    if (i.Name.ToLower() == name.ToLower())
                        return true;
                }
            }
            return false;
        }

        public object GetValue(string path) {
            if (path.ToLower().Contains("\\") && path.ToLower().IndexOf("\\") == path.ToLower().LastIndexOf("\\")) {
                var name = path.Substring(0, path.IndexOf("\\"));
                var property = path.Substring(path.IndexOf("\\") + 1);
                foreach (var i in keys) {
                    if (i.Name.ToLower() == name.ToLower() && i[property.ToLower()] != null)
                        return i[property.ToLower()].Value;
                }
            }
            return null;
        }


        public object GetValue(string path, object value) {
            if (path.ToLower().Contains("\\") && path.ToLower().IndexOf("\\") == path.ToLower().LastIndexOf("\\")) {
                var name = path.Substring(0, path.IndexOf("\\"));
                var property = path.Substring(path.IndexOf("\\") + 1);
                foreach (var i in keys) {
                    if (i.Name.ToLower() == name.ToLower() && i[property.ToLower()] != null)
                        return i[property.ToLower()].Value;
                }
            }
            return value;
        }

        public bool AddOrUpdate(string path, object value) {
            if (path.ToLower().Contains("\\") && path.ToLower().IndexOf("\\") == path.ToLower().LastIndexOf("\\")) {
                var name = path.Substring(0, path.IndexOf("\\"));
                var property = path.Substring(path.IndexOf("\\") + 1);
                bool find = false;
                foreach (var i in keys) {
                    if (i.Name.ToLower() == name.ToLower()) {
                        if (i[property.ToLower()] != null) {
                            i[property.ToLower()].Value = value;
                        } else i.Properties.Add(new Property(property, value));
                        find = true;
                        break;
                    }
                }
                if (!find) {
                    var ini = new IniKey(name);
                    keys.Add(ini);
                    ini.Properties.Add(new Property(property, value));
                }
                return true;
            }
            return false;
        }

        public object GetValue(string name, string property) {
            foreach (var i in keys) {
                if (i.Name.ToLower() == name.ToLower() && i[property.ToLower()] != null)
                    return i[property.ToLower()].Value;
            }
            return null;
        }

        public void Save() {
            StreamWriter sw = new StreamWriter(file);
            sw.BaseStream.Position = 0;
            string print = "";
            foreach (var i in keys) {
                print += "[" + i.Name + "]\r\n";
                foreach (var j in i) {
                    print += j.Key + "=" + j.Value + "\r\n";
                }
                print += "\r\n";
            }
            sw.Write(print);
            sw.Close();
        }

        internal void Reload() {
            Load(Filename);
        }
    }
}