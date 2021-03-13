---
layout: post
title: Search And Replace Across Multiple Files In Bash
date: 2011-01-11 16:21:34.000000000 -05:00
categories:
- Linux
- bash
- grep
- replace
- search
- sed
tags: []
permalink: "/2011/01/linux/search-and-replace-across-multiple-files-in-bash/"
---
When I need to do something like a search and replace across multiple files, I usually write a PHP script. I always knew I could do it faster with grep and sed, but I was too lazy to research how to do it. Last week I finally decided to find a better way. I'm entering it here so I can easily find it back.

You can use this technique to replace any string you want. For example, to change a class name you would do something like this:

`grep -RlZ OldClassName * | xargs -0l sed -i -e 's/OldClassName/NewClassName/g'`

## grep

grep will search through files for a regular expression. The R option make the search recursive so it will go down in the the directory structure. The l option tells grep to output only the names of files where it found a match. And with Z, grep will separate the results with \0 instead of \n, we will see later why this is necessary. You can also add the i option if you want to make a case insensitive search. After the options, we give grep the expression to search for and the files we want to search. In our case, we only search for a class name, but we could have used a regular expression.

## xargs

xargs is a tool used to build a command from the standard input. So instead of writing a loop to go through the results from grep and passing them as parameters to another command, we let xargs take care of it. It will execute the given command on all the files returned by grep. We give xargs the -0 option to tell it that a \0 instead of the whitespace it expect. This will allow us to process files with whitespace in the name. The l option is used so xargs will pass the file names 1 line at the time to sed.

## sed

sed is a stream editor. It take text from a stream (a file in this case), edit it in some way and output it back. In this case, we will pass it all the files found by grep and ask it to replace all occurrence of OldClassName with NewClassName. To make sed act on the files found by grep, we pass then using a pipe and xargs. We use the i option to make sed edit the file. If you give -i an extension, it will create a back up of the original file. The e options tells sed to add the string between quotes to the command. This is the regular expression to be executed. In this case, the expression is pretty simple. The s tells sed to replace OldClassName with NewClassName. The g at the ends make it global, so it replace all occurrences.

## Other Uses

The value of learning this technique is that it can be used to replace any string you want. With regular expressions, you can use it to replace a phone number across multiple html pages. It doesn't matter if there are hundreds of files, and if the phone number is repeated many times in each file. Just build the correct regex and you're set. And with the flexibility of regular expressions, you can replace one phone number, or any phone number found on your pages. If your files are under source control, you can easily look at the diff before committing the changes made by sed. If they are not, start by putting them in source control.

To me, this command shows the power of command line tools. They are built in a way that makes it easy to use them together, passing the result of a command to the next one. I really need to work on my knowledge of them and start using them more in my daily tasks.

