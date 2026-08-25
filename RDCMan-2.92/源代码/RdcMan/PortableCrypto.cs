using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace RdcMan
{
	internal static class PortableCrypto
	{
		private const string Prefix = "RDCManPortable1:";
		private const int KeySize = 32;
		private static readonly object SyncRoot = new object();
		private static byte[] _key;

		private static string KeyPath => PortablePaths.Combine("RDCMan.portable.key");

		public static string Encrypt(string plaintext)
		{
			if (string.IsNullOrEmpty(plaintext))
			{
				return null;
			}

			byte[] key = GetKey();
			byte[] iv = new byte[16];
			using (RandomNumberGenerator random = RandomNumberGenerator.Create())
			{
				random.GetBytes(iv);
			}

			byte[] ciphertext;
			using (Aes aes = Aes.Create())
			{
				aes.Key = key;
				aes.IV = iv;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;
				using (ICryptoTransform encryptor = aes.CreateEncryptor())
				{
					byte[] input = Encoding.UTF8.GetBytes(plaintext);
					ciphertext = encryptor.TransformFinalBlock(input, 0, input.Length);
				}
			}

			byte[] payload = new byte[iv.Length + ciphertext.Length];
			Buffer.BlockCopy(iv, 0, payload, 0, iv.Length);
			Buffer.BlockCopy(ciphertext, 0, payload, iv.Length, ciphertext.Length);
			byte[] mac;
			using (HMACSHA256 hmac = new HMACSHA256(key))
			{
				mac = hmac.ComputeHash(payload);
			}

			byte[] result = new byte[payload.Length + mac.Length];
			Buffer.BlockCopy(payload, 0, result, 0, payload.Length);
			Buffer.BlockCopy(mac, 0, result, payload.Length, mac.Length);
			return Prefix + Convert.ToBase64String(result);
		}

		public static string Decrypt(string encrypted)
		{
			if (string.IsNullOrEmpty(encrypted))
			{
				return string.Empty;
			}
			if (!encrypted.StartsWith(Prefix, StringComparison.Ordinal))
			{
				throw new FormatException("不是便携密码格式");
			}

			byte[] all = Convert.FromBase64String(encrypted.Substring(Prefix.Length));
			if (all.Length < 16 + 16 + 32)
			{
				throw new CryptographicException("便携密码数据不完整");
			}

			byte[] key = GetKey();
			int payloadLength = all.Length - 32;
			byte[] payload = new byte[payloadLength];
			byte[] expectedMac = new byte[32];
			Buffer.BlockCopy(all, 0, payload, 0, payload.Length);
			Buffer.BlockCopy(all, payload.Length, expectedMac, 0, expectedMac.Length);

			byte[] actualMac;
			using (HMACSHA256 hmac = new HMACSHA256(key))
			{
				actualMac = hmac.ComputeHash(payload);
			}
			if (!actualMac.SequenceEqual(expectedMac))
			{
				throw new CryptographicException("便携密码密钥不匹配");
			}

			byte[] iv = new byte[16];
			byte[] ciphertext = new byte[payload.Length - iv.Length];
			Buffer.BlockCopy(payload, 0, iv, 0, iv.Length);
			Buffer.BlockCopy(payload, iv.Length, ciphertext, 0, ciphertext.Length);
			using (Aes aes = Aes.Create())
			{
				aes.Key = key;
				aes.IV = iv;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;
				using (ICryptoTransform decryptor = aes.CreateDecryptor())
				{
					byte[] plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
					return Encoding.UTF8.GetString(plaintext);
				}
			}
		}

		private static byte[] GetKey()
		{
			lock (SyncRoot)
			{
				if (_key != null)
				{
					return _key;
				}

				if (File.Exists(KeyPath))
				{
					byte[] existing = File.ReadAllBytes(KeyPath);
					if (existing.Length == KeySize)
					{
						_key = existing;
						return _key;
					}
				}

				byte[] generated = new byte[KeySize];
				using (RandomNumberGenerator random = RandomNumberGenerator.Create())
				{
					random.GetBytes(generated);
				}
				string temporary = KeyPath + ".new";
				File.WriteAllBytes(temporary, generated);
				if (File.Exists(KeyPath))
				{
					File.Delete(temporary);
					_key = File.ReadAllBytes(KeyPath);
				}
				else
				{
					File.Move(temporary, KeyPath);
					_key = generated;
				}
				return _key;
			}
		}
	}
}
