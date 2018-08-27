#pragma once

#include <vector>
#include <memory>
#include <string>

#include <bf/all.hpp>
#include <sodium.h>

namespace crypto {

	inline std::string sha256_sum(const std::string& k)
	{
		std::string result(crypto_hash_sha256_BYTES, '\0');
		crypto_hash_sha256((unsigned char*)result.data(),
			(const unsigned char*)k.data(), k.size());
		return result;
	}

	template <std::size_t N>
	class xchacha20poly1305_inner_data
	{
	public:
		xchacha20poly1305_inner_data() {}
		xchacha20poly1305_inner_data(const std::string& k)
		{
			auto h = sha256_sum(k);
			BOOST_ASSERT(h.size() >= N);
			for (int i = 0; i < N; i++)
				key_[i] = (unsigned char)h[i];
		}

		std::string to_string() const
		{
			return { (const char*)&key_[0], (const char*)&key_[N] };
		}

		unsigned char* data()
		{
			return &key_[0];
		}

		const unsigned char* data() const
		{
			return &key_[0];
		}

		unsigned char key_[N];
	};

	class xchacha20poly1305_key
		: public xchacha20poly1305_inner_data<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
	{
	public:
		~xchacha20poly1305_key() = default;
		xchacha20poly1305_key() {}
		xchacha20poly1305_key(const std::string& k)
			: xchacha20poly1305_inner_data(k)
		{}

		static xchacha20poly1305_key from_string(const std::string& k)
		{
			return { k };
		}
	};

	class xchacha20poly1305_nonce
		: public xchacha20poly1305_inner_data<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>
	{
	public:
		~xchacha20poly1305_nonce() = default;
		xchacha20poly1305_nonce() {}
		xchacha20poly1305_nonce(const std::string& k)
			: xchacha20poly1305_inner_data(k)
		{}

		static xchacha20poly1305_nonce from_string(const std::string& nonce)
		{
			return { nonce };
		}
	};

	class xchacha20poly1305_crypto
	{
		// c++11 noncopyable.
		xchacha20poly1305_crypto(const xchacha20poly1305_crypto&) = delete;
		xchacha20poly1305_crypto& operator=(const xchacha20poly1305_crypto&) = delete;

	public:
		xchacha20poly1305_crypto()
			: m_bloom_filter(0.4, 100000000)
		{
			if (sodium_init() == -1)
				LOG_ERR << "sodium_init fail!";
		}
		~xchacha20poly1305_crypto()
		{}

	public:
		// 指定nonce加密, 加密后的数据尾部不带nonce.
		std::vector<uint8_t> encrypt(std::vector<uint8_t>& message,
			std::vector<uint8_t>& additional,
			const xchacha20poly1305_nonce& nonce, const xchacha20poly1305_key& key)
		{
			std::vector<uint8_t> result(message.size() +
				crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);
			unsigned long long ciphertext_len;
			crypto_aead_xchacha20poly1305_ietf_encrypt(result.data(), &ciphertext_len,
				message.data(), message.size(),
				additional.data(), additional.size(),
				NULL, nonce.data(), key.data());
			result.resize(ciphertext_len);
			return result;
		}

		// 随机nonce加密, 加密后的数据尾部带上随机nonce.
		std::vector<uint8_t> encrypt(std::vector<uint8_t>& message,
			std::vector<uint8_t>& additional, const xchacha20poly1305_key& key)
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
				NULL, nonce, key.data());
			std::memmove(&result[ciphertext_len], nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
			result.resize(ciphertext_len + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
			return result;
		}

		std::vector<uint8_t> decrypt(const void* ciphertext, std::size_t ciphertext_len,
			const void* additional, std::size_t additional_len,
			const xchacha20poly1305_nonce& nonce, const xchacha20poly1305_key& key)
		{
			std::vector<uint8_t> result(1024 * 1024, 0);
			unsigned long long decrypted_len;
			if (m_bloom_filter.lookup(nonce.to_string()))
			{
				result.resize(0);
				return result;
			}
			m_bloom_filter.add(nonce.to_string());
			if (crypto_aead_xchacha20poly1305_ietf_decrypt(result.data(), &decrypted_len,
				NULL, (const unsigned char*)ciphertext, ciphertext_len,
				(const unsigned char*)additional, additional_len,
				nonce.data(), key.data()) != 0)
			{
				result.resize(0);
				return result;
			}
			result.resize(decrypted_len);
			return result;
		}

		std::vector<uint8_t> decrypt(std::vector<uint8_t>& ciphertext,
			std::vector<uint8_t>& additional,
			const xchacha20poly1305_nonce& nonce, const xchacha20poly1305_key& key)
		{
			return decrypt(ciphertext.data(), ciphertext.size(),
				additional.data(), additional.size(), nonce, key);
		}

		std::vector<uint8_t> decrypt(const void* ciphertext, std::size_t ciphertext_len,
			const void* additional, std::size_t additional_len, const xchacha20poly1305_key& key)
		{
			std::vector<uint8_t> result(1024 * 1024, 0);
			unsigned long long decrypted_len;
			auto data_len = ciphertext_len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
			if (data_len <= 0)
			{
				result.resize(0);
				return result;
			}
			auto nonce = &((const unsigned char*)ciphertext)[data_len];
			auto nonce_obj = bf::object(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
			if (m_bloom_filter.lookup(nonce_obj))
			{
				result.resize(0);
				return result;
			}
			m_bloom_filter.add(nonce_obj);
			if (crypto_aead_xchacha20poly1305_ietf_decrypt(result.data(), &decrypted_len,
				NULL, (const unsigned char*)ciphertext, data_len,
				(const unsigned char*)additional, additional_len,
				nonce, key.data()) != 0)
			{
				result.resize(0);
				return result;
			}
			result.resize(decrypted_len);
			return result;
		}

		std::vector<uint8_t> decrypt(std::vector<uint8_t>& ciphertext,
			std::vector<uint8_t>& additional, const xchacha20poly1305_key& key)
		{
			return decrypt(ciphertext.data(), ciphertext.size(),
				additional.data(), additional.size(), key);
		}

	private:
		bf::basic_bloom_filter m_bloom_filter;
	};
}
