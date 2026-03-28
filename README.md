# GFW IP List

Partial list of IP addresses blocked by the GFW (Great Firewall), which can be used to configure routing tables to route traffic through VPN.

Sites pointing to CDN are not included.

Severely incomplete, contributions welcome.

## FAQ

**Q: I added these routes but still cannot access the sites**

A: It might be because DNS is polluted, resulting in incorrect IP resolution. Please configure a pollution-resistant DNS.

**Q: How do I know which domains are polluted?**

A: You can check the complete list of blocked URLs [here](https://github.com/gfwlist/gfwlist).
   However, this list does not distinguish between IP blocking and domain pollution.
   If you want a quick solution, you can add all domains from this list to pollution protection, regardless of the cause.
   If you prefer a more precise approach, you can write a script to filter out only the truly polluted domains.
   [Here](https://github.com/wongsyrone/domain-block-list) is a ready-made quick solution list.

**Q: The list mentioned above does not include cases where CSS/JS/images and other resource files are polluted**

A: I have additionally compiled a gfwdomainlist.txt containing a list of CDN domains that may be polluted.
   Contributions welcome.

## Project Structure

- `gfwiplist.txt` - The generated IP list file
- `misc/generate.py` - Python script to generate the IP list
- `misc/gfwdomainlist.txt` - List of potentially polluted CDN domains
- `misc/requirements.txt` - Python dependencies

## Usage

```bash
cd misc
pip install -r requirements.txt
python generate.py > ../gfwiplist.txt
```

## License

[WTFPL V2](http://www.wtfpl.net/txt/copying/)

<a href="http://www.wtfpl.net/"><img
       src="http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png"
       width="80" height="15" alt="WTFPL" /></a>

<pre>
            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
</pre>
