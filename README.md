GFW 境外列表（部分），可用于设置路由表走 VPN

指向 CDN 的网站没有包含进去。

严重不全，欢迎补充。

## FAQ

Q: 我加上了这些路由仍然访问不了

A: 可能是因为 DNS 被污染了导致解析的 IP 不对。请配置一个可以防污染的 DNS

Q: 如何知道哪些域名被污染了？

A: 你可以在 [这里](https://github.com/gfwlist/gfwlist) 查到被墙 URL 的完整列表。
   但是这个列表并没有区分是 IP 被封锁还是域名被污染。
   如果你偷懒，可以把这个列表涉及到的所有域名都加入到防污染中，不管原因。
   如果你勤快，可以写个脚本过滤出来其中真正的污染的域名列表。

Q: 上面问题中涉及到的列表，不包含 css/js/图片 等资源文件被污染的情况

A: 我额外整理了一份 gfwdomainlist.txt，上面有涉及到可能被污染的 CDN 的域名列表
   欢迎补充

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
