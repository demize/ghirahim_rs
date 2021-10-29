==============================================
Ghirahim_Bot: A Twitch IRC bot to defeat links
==============================================

**Ghirahim_Bot** is a Twitch IRC bot designed specifically to delete links from chat without timing users out, and with robust link detection. It will delete individual messages, and it will only detect links with valid TLDs: no more erasing someone's whole chat history because they forgot a space!

If you just want to use the bot, the instructions are in the next section. If you want to run the bot yourself, skip to the `Running the bot yourself section <#running-the-bot-yourself>`_.

Using the bot without running it
--------------------------------

The bot should be running as the Twitch user Ghirahim_Bot, and you can use it!

Joining and leaving
^^^^^^^^^^^^^^^^^^^

Joining
"""""""

To have the bot join your channel, go to `its channel <https://twitch.tv/Ghirahim_Bot>`_ and type ``!join``. It will respond indicating it's joined your channel. It's possible that it might fail to join if it's up against the rate limit; if it doesn't respond to commands in your channel, you can always tell it to ``!join`` again.

Once the bot joins your channel you need to add it as a mod for it to function (``/mod Girahim_Bot``). If you do not make the bot a mod, and it tries to delete a message, send duplicate messages, or send messages too quickly, then it will put your channel in a 5-minute cooldown. While in this cooldown, it will not respond to any messages in your channel (commands or messages with links).

By default, the bot will delete any link posted by anyone who is not a VIP, mod, or the broadcaster. See the `configuring the bot section <#configuring-the-bot>`_ for details on how to allow specific domains or change the default settings.

Leaving
"""""""

To have the bot leave your channel, go to its channel and type ``!leave``. It will no longer respond to commands or delete messages in your channel. It should leave immediately, but again, it's possible it could run up against the rate limit; if this is the case, it will leave the next time it receives a message in your channel.

The bot also checks hourly to ensure it's in every channel it should be and not in any it shouldn't be.

Configuring the bot
^^^^^^^^^^^^^^^^^^^

The bot offers a number of configuation commands:

+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+
| Command            | Description                                                                                                                                                                                                                                                      | Default                                                         | Valid values                                              |
+====================+==================================================================================================================================================================================================================================================================+=================================================================+===========================================================+
| !links list        | Print the current allow list for the channel                                                                                                                                                                                                                     | Empty                                                           | N/A                                                       |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+
| !links allow       | Add a new link to the allow list                                                                                                                                                                                                                                 | N/A                                                             | Any domain (or a list of space-separated domains)         |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+
| !links deny        | Remove a link from the allow list                                                                                                                                                                                                                                | N/A                                                             | Any domain (or a list of space-separated domains)         |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+
|| !links slash      || Slash matching: if enabled, URLs will be considered for removal if they have a slash in them. If disabled, they will be considered for removal regardless of a slash.                                                                                           || Yes                                                            || Enable: yes, true                                        |
||                   || (e.g. ``google.com/`` or ``https://google.com`` (if Yes) or just ``google.com`` (if No))                                                                                                                                                                        ||                                                                || Disable: no, false                                       |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+
|| !links dot        || Dot matching: if enabled, URLs will be considered for removal if they have more than one dot (e.g. ``www.google.com`` or ``example.org/index.html``).                                                                                                           || Yes                                                            || Enable: yes, true                                        |
||                   || This has practically no effect if slash matching is disabled; it is designed to counteract some of the downsides of slash matching.                                                                                                                             ||                                                                || Disable: no, false                                       |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+
|| !links subdomains || Whether to match domains including subdomains or strictly                                                                                                                                                                                                       ||                                                                || Include: yes, true                                       |
||                   || (e.g. whether ``www.google.com`` would be allowed by ``google.com`` or not)                                                                                                                                                                                     || Yes                                                            || Strict matching: no, false                               |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+
|| !links role       || The minimum role a user must have to be allowed to post links                                                                                                                                                                                                   || VIP                                                            || Subscriber, VIP, Moderator                               |
||                   || Roles are evaluated according to the following hierarchy: Broadcaster > Moderator > VIP > Subscriber > User. Setting the role to Moderator or higher will prevent anyone but moderators from posting links; setting it to User will allow anyone to post links. ||                                                                || (User and Broadcaster will work but are not recommended) |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+
| !links reply       | How to reply to users when their messages are deleted. Put ``__user__`` or ``@__user__`` in the reply message to specify where the user is mentioned; otherwise a user mention will be prefixed to the beginning of the message.                                 | ``@__user__, please ask for permission before posting a link.`` | Any string                                                |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------+-----------------------------------------------------------+

The ``allow`` command and ``deny`` command can also be called as ``add`` and ``remove``/``del`` respectively.

If you want to test your channel settings, you can use the ``!links test`` command. Any text following ``!links test`` will be parsed per your channel settings, and the bot will reply saying whether it would have deleted the message or not.

Advanced URL matching
^^^^^^^^^^^^^^^^^^^^^

The bot has support for two additional features when matching URLs: wildcards and regexes.

You can provide a wildcard domain in the format ``*.example.org`` and it will match any subdomains of that domain. Note that this will truly match *any* subdomain, i.e. ``a.b.example.org`` and ``a.example.org`` will both match.

You can also provide a regex to match on. Note that there is a tight timeout on regex execution, and the bot will remove any regexes where the timeout expires (with a message in chat advising you of it). To add a regex, use the format ``/regex/``. 

Using the bot
^^^^^^^^^^^^^

Once configured, the bot will work by itself. Unless you need to change any further settings, you will not need to use the ``!links`` commands again.

To allow a user to post a link temporarily, issue the user a permit with ``!permit <user>``. The user specified will be allowed to post links for 5 minutes.

Limitations
^^^^^^^^^^^

- The bot will not detect links that are hidden/obfuscated. In general, if you can click on them and they're real, it will detect them; if you can't click on them, it will ignore them.
- The bot will mistakenly detect links from mistyped messages (e.g. ``hello.how are you doing``) if the mistyped message includes a valid domain (with a valid TLD per IANA's current list). To prevent this, you can turn on the ``slash`` option (which is enabled by default). If the ``slash`` option is too lenient, you can also enable the ``dot`` option to detect links that contain multiple dots.


Running the bot yourself
------------------------

Ghirahim_Bot is not designed to be a self-bot, and currently does not have built-in support for specifying its own channel; to run it yourself, you will need to modify the source. That said, you can run it yourself so long as you have a bot account, a mongodb server, and a redis server. Just copy ``ghirahim.yaml.sample`` to ``ghirahim.yaml``, make the necessary edits, build the bot, and run it. 

Prerequisites 
^^^^^^^^^^^^^

This bot was built and tested with Rust 1.56.0. It requires its own Twitch account, a MongoDB server, and a Redis server. Redis is not optional; it's built in to the bot logic, and the ``!permit`` command is implemented entirely with Redis. The following packages are also required (exact packages may vary based on your OS and package manager):

- C compiler/linker/ar (just install build-essential on Ubuntu/Debian)
- libssl-dev
- pkg-config

Setup
^^^^^

All config is kept in ``girahim.yaml``. Copy ``ghirahim.yaml.sample`` to ``ghirahim.yaml`` and edit the settings. You need an oauth password for the account you intend to use; the easiest option is to generate one with `twitchapps <https://twitchapps.com/tmi/>`_. Ensure it follows the format ``oauth:your_oauth_token`` (including the ``oauth:`` prefix) or the bot will be unable to log in. You'll also need to provide a MongoDB server and Redis server, with credentials in the formats specified.

Running the bot
^^^^^^^^^^^^^^^

The executable produced by cargo (target/\*/ghirahim_bot) can be copied out of the target directory and run directly. Running the bot under its own account is recommended. It can be easily run as a service with a basic systemd unit file; it does not fork, so it should be run with exec, and it will print all log messages to stdout to be caught and logged by systemd. You should probably build it with the ``--release`` flag for optimizations, especially if running it on a relatively low-powered server.