#!/usr/bin/ruby

#
# When you have acquired a list of flow sizes in a text file named lengths.txt
# use this script to extract the delta factor from it.
#
# Usage: ./sortlengths.rb
#

words = File.open("lengths.txt") {|f| f.read }.split

values = Array.new(0)
words.each { |value| values << value.to_i }
values.sort!
values.uniq!

diffs = Array.new(0)
sum = 0
s = 0
values.each_index { |index| if index.to_i < values.length-1 then sum += values.at(index.to_i + 1) - values.at(index.to_i) end }
puts "delta has the value of\n"
puts values.at(0) / 2
