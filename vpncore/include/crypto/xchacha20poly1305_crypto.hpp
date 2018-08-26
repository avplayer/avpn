#pragma once

#include <vector>
#include <memory>
#include <string>

#include <bf/all.hpp>
#include <sodium.h>

namespace crypto {

	class xchacha20poly1305_crypto
	{
		// c++11 noncopyable.
		xchacha20poly1305_crypto(const xchacha20poly1305_crypto&) = delete;
		xchacha20poly1305_crypto& operator=(const xchacha20poly1305_crypto&) = delete;

	public:
		typedef unsigned char nonce_type[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
		typedef unsigned char key_type[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

		xchacha20poly1305_crypto()
			: m_bloom_filter(0.4, 100000000)
		{
			std::memset(m_key, 0, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
			sodium_init();
		}
		~xchacha20poly1305_crypto()
		{}

	public:
		// 指定nonce加密, 加密后的数据尾部不带nonce.
		std::vector<uint8_t> encrypt(std::vector<uint8_t>& message,
			std::vector<uint8_t>& additional, nonce_type& nonce)
		{
			std::vector<uint8_t> result(message.size() +
				crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);
			unsigned long long ciphertext_len;
			crypto_aead_xchacha20poly1305_ietf_encrypt(result.data(), &ciphertext_len,
				message.data(), message.size(),
				additional.data(), additional.size(),
				NULL, nonce, m_key);
			result.resize(ciphertext_len);
			return result;
		}

		// 随机nonce加密, 加密后的数据尾部带上随机nonce.
		std::vector<uint8_t> encrypt(
			std::vector<uint8_t>& message, std::vector<uint8_t>& additional)
		{
			std::vector<uint8_t> result(message.size() +
				crypto_aead_xchacha20poly1305_ietf_ABYTES +
				crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 0);
			unsigned long long ciphertext_len;
			auto nonce = &result[message.size() +
				crypto_aead_xchacha20poly1305_ietf_ABYTES];
			randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
			crypto_aead_xchacha20poly1305_ietf_encrypt(result.data(), &ciphertext_len,
				message.data(), message.size(),
				additional.data(), additional.size(),
				NULL, nonce, m_key);
			std::memmove(&result[ciphertext_len], nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
			result.resize(ciphertext_len + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
			return result;
		}

		std::vector<uint8_t> decrypt(std::vector<uint8_t>& ciphertext,
			std::vector<uint8_t>& additional, nonce_type& nonce)
		{
			std::vector<uint8_t> result(1024 * 1024, 0);
			unsigned long long decrypted_len;
			if (m_bloom_filter.lookup(nonce))
			{
				result.resize(0);
				return result;
			}
			m_bloom_filter.add(nonce);
			if (crypto_aead_xchacha20poly1305_ietf_decrypt(result.data(), &decrypted_len,
				NULL, ciphertext.data(), ciphertext.size(),
				additional.data(), additional.size(), nonce, m_key) != 0)
			{
				result.resize(0);
				return result;
			}
			result.resize(decrypted_len);
			return result;
		}

		std::vector<uint8_t> decrypt(std::vector<uint8_t>& ciphertext,
			std::vector<uint8_t>& additional)
		{
			std::vector<uint8_t> result(1024 * 1024, 0);
			unsigned long long decrypted_len;
			auto data_len = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
			if (data_len <= 0)
			{
				result.resize(0);
				return result;
			}
			auto nonce = &ciphertext[data_len];
			auto nonce_obj = bf::object(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
			if (m_bloom_filter.lookup(nonce_obj))
			{
				result.resize(0);
				return result;
			}
			m_bloom_filter.add(nonce_obj);
			if (crypto_aead_xchacha20poly1305_ietf_decrypt(result.data(), &decrypted_len,
				NULL, ciphertext.data(), data_len,
				additional.data(), additional.size(), nonce, m_key) != 0)
			{
				result.resize(0);
				return result;
			}
			result.resize(decrypted_len);
			return result;
		}

		const key_type& key() const
		{
			return m_key;
		}

		void key(const std::string& k)
		{
			auto size = std::min<std::size_t>(k.size(),
				crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
			std::memset(m_key, 0, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
			std::memcpy(m_key, k.data(), size);
		}

	private:
		bf::basic_bloom_filter m_bloom_filter;
		key_type m_key;
	};
}
