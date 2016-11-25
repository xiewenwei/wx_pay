require 'active_support/core_ext/hash/conversions'

module WxPay
  module Utils
    def self.xml_to_hash(xml)
      Hash.from_xml(xml)
    end
  end
end
