---
layout: post
title: Installing the TICK Stack Tools to Collect Metrics
date: 2018-03-30 16:45:45.000000000 -04:00
type: post
tags:
- Monitoring
- TICK Stack
permalink: "/2018/03/tick-stack/installing-tick-stack-tools-metrics/"
img: 2018/03/TickData.jpg
---

<p>The <a href="https://www.influxdata.com/time-series-platform/">TICK Stack</a> is a great platform if you want to gain some visibility over your applications. However, looking into how to install it can be a little overwhelming. There are four tools that you need to install to use it:</p>
<ul>
<li>Telegraf to collect the data</li>
<li>InfluxDB to store the data</li>
<li>Chronograf, the UI to view the data</li>
<li>Kapacitor to process the data in real time</li>
</ul>
<p>All these tools are documented individually, with instructions on how to install them. But I wanted to have simple instructions to install all of them in Ubuntu and get started quickly.</p>
<h2>Installing the Tools</h2>
<p>First, add the InfluxData repository to your machine</p>
<pre>curl -sL https://repos.influxdata.com/influxdb.key | sudo apt-key add -
source /etc/lsb-release
echo "deb https://repos.influxdata.com/${DISTRIB_ID,,} ${DISTRIB_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/influxdb.list
</pre>
<p>Then install the applications</p>
<pre>sudo apt-get update &amp;&amp; sudo apt-get install influxdb telegraf chronograf kapacitor</pre>
<p>To configure Telegraf, edit the file <em>/etc/</em>telegraf<em>/telegraf.conf</em> and uncomment the <em>[[inputs.statsd]]</em> section.</p>
<p>Inside the statsd section, uncomment the templates and add the templates you need. You can find more information on the format of the templates in the <a href="https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_INPUT.md#graphite">Telegraf documentation</a>.</p>
<pre>templates = [
 "cpu.* measurement*",
 "blog.views.* measurement.measurement.page.field"
]</pre>
<p>Now make sure all the needed service are started.</p>
<pre>sudo service influxdb restart 
sudo service telegraf restart 
sudo service chronograf restart 
sudo service kapacitor restart
</pre>
<h2>Configure the UI</h2>
<p>Chronograf is installed, and listening on port 8888. I installed in in a <a href="https://puphpet.com/">PuPHPet VM</a>, so mine is available at <a href="http://192.168.56.101:8888">http://192.168.56.101:8888. </a></p>
<p><img class="alignnone wp-image-1233" src="{{ site.baseurl }}/assets/images/2018/03/TickInfluxConnection.jpg" alt="" width="552" height="370" /></p>
<p>You can leave all the default values and click on Add connection.</p>
<p>Next, you will need to configure Kapacitor. Click on Configuration in the left toolbar.</p>
<p><img class="alignnone wp-image-1235" src="{{ site.baseurl }}/assets/images/2018/03/TickAddKapacitor.jpg" alt="" width="634" height="193" /></p>
<p>Click on Add Kapacitor Connection in the Configuration page, leave all the Kapacitor settings to their defaults and click on Connect.</p>
<p><img class="alignnone wp-image-1236" src="{{ site.baseurl }}/assets/images/2018/03/TickConfigureKapacitor.jpg" alt="" width="647" height="317" /></p>
<p>&nbsp;</p>
<h2>Test The Applications</h2>
<p>Log data to the template you created earlier.</p>
<pre>echo "blog.views.home.pageview:1|c" | nc -w 1 -u 127.0.0.1 8125</pre>
<p>Check in the database for the data you inserted.</p>
<pre>$ influx
Connected to http://localhost:8086 version 1.5.1
InfluxDB shell version: 1.5.1
> use telegraf
Using database telegraf
> select * from blog_views
name: blog_views
time host metric_type page pageview
---- ---- ----------- ---- --------
1522440310000000000 machine1 counter home 2 1522440320000000000 machine1 counter home 1

You should also be able to see the inserted data in Chronograf.

Click on Data Explorer in the left side menu. Choose telegraf.autogen&nbsp;DB, and explore your data.

<p><img class="alignnone wp-image-1235" src="{{ site.baseurl }}/assets/images/2018/03/TickData.jpg" alt="Cronograf Data Explorer"  /></p>

