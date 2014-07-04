# Ip range verifyer incase of ddos
require "ipaddr"
require File.expand_path("../rate-limiting/range_list", __FILE__) 

class IpRange

  PATH_TO_FILE = File.expand_path("../rate-limiting/datacenters.csv", __FILE__)
  attr_accessor :ip_range
  def initialize
    @ip_range = Rate::Limiting::RangeList::IPRANGE
    @count = @ip_range.count
  end

  def read_from_csv
    text = File.open(PATH_TO_FILE).read
    text.gsub!(/\r\n?/, "\n")
    text.each_line do |line|
      next if line.match(/^#/)
      ip_range_list = line.split(",")
      construct_array(ip_range_list)
    end
  end

  def construct_array(ip_range_list)
    ip_range_list[0] = IPAddr.new(ip_range_list[0]).to_i
    ip_range_list[1] = IPAddr.new(ip_range_list[1]).to_i
    @ip_range << ip_range_list
  end

  def check_presence_of_ip(ip)
    ip = IPAddr.new(ip).to_i
    binary_search(ip)
  end

  def binary_search(ip)
    haystack = @ip_range
    high = @count - 1
    low = 0
    while (high >= low) do
      probe = (high + low) / 2
      row = haystack[probe]
      if (row[0] > ip)
        high = probe - 1
      elsif(row[1] < ip)
        low = probe + 1
      else
        return row
      end
    end
    return nil
  end
    
end
