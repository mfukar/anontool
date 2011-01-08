#!/usr/bin/ruby
# When you have acquired a list of flow sizes in a text file named
# lengths.txt use this script to extract the delta factor from it.
#
# Usage: ./sortlengths.rb
#
# Read integer numbers from file, sort them ASC and remove duplicates
values = File.read("lengths.txt").split.map(&:to_i).sort.uniq
# Take pairwise combinations of values and calculate the total sum
sum = values.each_cons(2).map { |a, b| b - a }.inject(0, :+)
# Compute and print the average
puts "delta has the value of %d" % sum / values.length
