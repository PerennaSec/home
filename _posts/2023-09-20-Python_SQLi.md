---
layout: post
title: Exploiting Blind & Restricted SQL Injections with Python
date: 2023-09-20
desc: Facilitate Data Extraction via Python's Requests Library
keywords: blog,website,python,linux,appsec,gh-pages,security,network,scripting,PerennaSec,automation
categories:
  - Python
tags:
  - Automation
  - Security
  - Python
icon: icon-html
---
*referenced scripts can be found at https://github.com/PerennaSec/Python-SQLi*

The beauty of finding a SQL Injection vulnerability in the wild is matched only by the brilliance of a well-written exploit script. Even in one's own security lab, it's an exciting pursuit; to be able to so delicately extract information by speaking the language of the database feels classically hacker. Indeed, it's one of the industry's most well-established, almost vintage, vulnerabilities. 

This post does not aim to be one's SQL Injection primer; for the purposes of this post it's best to know that a blind SQL injection is one for which the vulnerability's code only allows boolean return values. When interfacing with a classic SQL Injection vulnerability, an attacker can typically expect their requested data to be returned intact -- for example, a password will be returned as 'password' (or some hashed text, ideally). With Blind SQL Injection vulnerabilities, output is returned from the exploited web application via boolean queries. An attacker will pose a series of queries to an application that return either a yes or a no -- a T/F response. Values are returned one character at a time, whether the attacker seeks usernames, passwords, or other valuable information. For this reason, these vulnerabilities are referred to as Blind Injections, as carrying out these attacks often feels as though one is progressing slowly -- blindly -- through a database. 

Classic SQL Injections are, at their core, malicious queries. A simple example is the tried-and-true ``select ID from USER where ID = [num] >=0``. A Blind Injection query looks similar, however they rely primarily upon SQL's ``substr()`` function. To discover password length, Python is used to iterate through the following query until the correct password length is found: ``select length(PASSWORD) from USER where ID = [num] and length(PASSWORD) <= {i}``. Here, an earlier-discovered user id can be substituted for `[num]`, and Python will be used to increase the value of `{i}`. After uncovering the correct password length, Python iterates through the length of the string one character at a time, passing attempts at the correct value by iterating through a given character set : 

```python
def boolean_query(offset, user_id, character, operator=">"): #determine valid characters for hash
  payload = f"(select hex(substr(password,{offset+1},1)) from user where id = {user_id}) {operator} hex('{character}')"
  return injected_query(payload)

...

def extract_hash(charset, user_id, password_length): #find pass hash
  found = ""
  for i in range(0, password_length):
    for j in range(len(charset)):
      if boolean_query(i, user_id, charset[j]):
        found += charset[j]
        break
  return found
```

This structure will be familiar to many Offensive Security Researchers, however I wanted to include it because of its use of fundamental Python interpreter mechanics. When iterating through nested lists, Python will evaluate the entirety of the nested list's values before moving on to the next value in the parent list. For our example above, this means that for every value of `i`, `j` will iterate entirely before moving on to the next `i` value. In other words, for every character position (what SQL refers to as ``substr()``) within the discovered password string, Python will utilize the `boolean_query()` function to test whether each character within the given `charset` is the correct character. When it finds the correct character for each index value, it appends that character to the `found` string, before moving on to the next position along the index. 

While this functionality performs perfectly well within a lab setting, modern defenses are more than adequately equipped to deal with simple SQL Injection vulnerabilities. Even if one can evade WAF filters and input sanitization, rate limited requests are most certainly the norm for any well-designed web application. 

Consider a scenario in which an attacker is only allowed 128 queries before being blocked by the application. The methods described above can easily equate to thousands of requests, and will leak into the tens of thousands if more robust password hashing methods are used. Consider the case of a 32-character MD5 hash.  If an attacker is allowed 128 queries, and 16 possible characters (`abcdef0123456789`), four characters can be guessed per index value. Under these restrictions, how could an attacker correctly extract the password hash?

The answer utilizes the polar nature of Boolean logic to its utmost. Given a 16-character `charset`, the value of the unknown character is compared against the middle via `<` or `>` operators. Consider the following: 

```python
### 0123456789abcdef >7? False

### 01234567 >3? True

### 34567 >5? True

### 567 >6? False
```

The first query allows half of the character set to be eliminated from consideration, regardless of which operator is used. Three subsequent queries amount to three subsequent halvings, the result of which leaves only one possible valid value. When performing binary searches, it helps to seek values that are adjacent to one another in the given `charset`. In the example above, the queries tell reveal that the unknown value is greater than five, but not greater than six. Therefore the value must be six.

In a script designed to exploit Restricted Blind SQL Injection, a simple augmentation is all that's needed from existing Blind SQL Injection scripts:

```python
def extract_hash_bst(charset, user_id, password_length): #perform binary hash extraction
  found = ""
  for index in range(0, password_length):
    start = 0
    end = len(charset) - 1
    while start <= end:
      if end - start == 1: #if values are next to eachother!
        if start == 0 and boolean_query(index, user_id, charset[start]): #check to include or exclude zero
          found += charset[start]
        else:
          found += charset[start + 1]
        break
      else:
		middle = (start + end) // 2
		if boolean_query(index, user_id, charset[middle]):
		  end = middle
		else:
		  start = middle
  return found
```

After navigating a set of disqualifying conditionals that first check the validity of the value `0`, as well as checking for cases in which the list of possible values is only two values long, the `middle` is found and the same `boolean_query()` function is called as before, passing a similar set of arguments. The results of the query are assigned to whichever variable is appropriate given the circumstance, either `end` or `start`. 

Underneath all this query, logic, and iteration lies a simple and robust Python tooling that allows for efficient diagnosis and exploitation of suspected vulnerabilities. For proof-of-concept purposes, a collection of valid user id's can be collected, along with their associated password hashes. One of Python's great strengths can be seen in its flexibility and dynamism while interfacing with web applications, networking architectures, and especially other programming languages. These simple SQL Injection PoC's simply scratch the surface of what can be accomplished.
