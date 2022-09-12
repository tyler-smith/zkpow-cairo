#!/usr/bin/env ruby
require 'json'


def parse_opts
    argv_0 = (ARGV[0] || "").downcase.gsub(/^--?/, '')
    all = argv_0 == "all"
    {
        all: all,
    }
end

def remove_non_input_words(words)
    words = [words[0], words[9..16], words[17], words[19]].flatten
    # words.map{|w| little_to_big_endian(w) }
end

def pad_hex_str(hex)
    ("0"*(8-hex.size)) + hex
end

def little_to_big_endian(word)
    padded_hex_str = pad_hex_str(word.to_s(16))
    padded_hex_str.scan(/(..)(..)(..)(..)/).first.reverse.join.to_i(16)
end

def main
    opts = parse_opts()
    puts STDIN.read.split("\n").map{|raw_header| 
        raise "Invalid header size #{raw_header.size}" unless raw_header.size == 160
        words = raw_header.chars.each_slice(8).map(&:join).map{|word| word.to_i(16) }
        words = remove_non_input_words(words) unless opts[:all]
        words
    }.to_json
end

main