using System;
using System.IO;
using System.Reflection;

namespace RdcMan
{
	internal static class PortablePaths
	{
		public static string BaseDirectory
		{
			get
			{
				string location = Assembly.GetExecutingAssembly().Location;
				string directory = Path.GetDirectoryName(location);
				return string.IsNullOrEmpty(directory) ? Environment.CurrentDirectory : directory;
			}
		}

		public static string Combine(string fileName)
		{
			return Path.Combine(BaseDirectory, fileName);
		}
	}
}
