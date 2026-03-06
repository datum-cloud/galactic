class FilterModule(object):
    def filters(self):
        return {
            'ipv4': self.ipv4_filter,
            'ipv6': self.ipv6_filter,
            'macaddr': self.macaddr_filter,
            'ipaddr': self.ipaddr_filter,
            'hwaddr': self.hwaddr_filter  # Added this mapping
        }

    def hwaddr_filter(self, value, query=None):
        """
        Simplified hwaddr filter to handle MAC formatting.
        Usage: {{ mac | hwaddr('linux') }}
        """
        if not value:
            return ""
        
        # Clean the input (remove dots, dashes, colons) to get raw hex
        clean_mac = str(value).replace(':', '').replace('-', '').replace('.', '').lower()
        
        # Format as Linux style (aa:bb:cc:dd:ee:ff)
        if query == 'linux' or not query:
            return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))
        
        # Format as Cisco style (aaaa.bbbb.cccc)
        if query == 'cisco':
            return '.'.join(clean_mac[i:i+4] for i in range(0, 12, 4))
            
        return clean_mac

    def ipaddr_filter(self, value, query=None):
        if not value: return ""
        if query == 'address':
            return str(value).split('/')[0]
        if query == 'prefix':
            return str(value).split('/')[1] if '/' in str(value) else ""
        return str(value)

    def ipv4_filter(self, value):
        if not value: return ""
        return str(value).split('/')[0]

    def ipv6_filter(self, value):
        if not value: return ""
        return str(value).split('/')[0].lower()

    def macaddr_filter(self, value):
        if not value: return ""
        return str(value).lower()
