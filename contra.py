#!/usr/bin/python

import os
import json
import requests
import pymysql
import pandas
from jsondiff import diff
from contextlib import closing
from pymysql.cursors import DictCursor
import json_tools as jt
from datetime import datetime
import time

class DatabaseOP(object):

	def __init__(self, cluster, host, user, password, db):
		self.cluster = cluster
		self.host = host
		self.user = user
		self.password = password
		self.db = db

	#Database methods
	def checkDB(self):
		print("Checking if database exists..")
		database = False
		with closing(pymysql.connect(
			host= self.host,
                        user= self.user,
                        password= self.password,
                        charset='utf8mb4',
                        cursorclass=DictCursor
			)) as conn:
				with conn.cursor() as cursor:
					query = 'show databases;'
					cursor.execute(query)
					result = cursor.fetchall()
		for i in result:
			if i["Database"] == self.db:
				database = True
		if database == True:
			print("Database exists: " + self.db)
			print("Cheking table...")
			self.checkTable()
		else:
			print("No such database or wrong identify")
			print("Creating a database...")
			self.dbCREATE()
			print("Cheking table...")
			self.checkTable()

	def checkTable(self):
		tableExists = False
		with closing(pymysql.connect(
			host= self.host,
			user= self.user,
			password= self.password,
			db = self.db,
			charset='utf8mb4',
			cursorclass=DictCursor
			)) as conn:
				with conn.cursor() as cursor:
					query = 'show tables;'
					cursor.execute(query)
					result = cursor.fetchall()
		for i in result:
			if (len(result) != 0) and i == {'Tables_in_' + self.db: 'control'}:
				tableExists = True
		if tableExists == True:
			print("Table exists, that's good.")
		else:
			print("Table not exists, creating....")
			self.tableCREATE()
			tableExists = True

	def dbCREATE(self):
		with closing(pymysql.connect(
			host= self.host,
			user= self.user,
			password= self.password,
			charset='utf8mb4',
			cursorclass=DictCursor
		)) as conn:
			with conn.cursor() as cursor:
				query = "CREATE DATABASE " + self.db + ";"
				cursor.execute(query)
				conn.commit()
		print("Database created!!!")

	def tableCREATE(self):
		with closing(pymysql.connect(
			host= self.host,
			user= self.user,
			password= self.password,
			db= self.db,
			charset='utf8mb4',
			cursorclass=DictCursor
		)) as conn:
			with conn.cursor() as cursor:
                		query = "CREATE TABLE control(cluster VARCHAR(35) NOT NULL,  service VARCHAR(20) NOT NULL, id VARCHAR(10) NOT NULL,  version VARCHAR(10) NOT NULL, boxnum VARCHAR(10) NOT NULL, type VARCHAR(20) NOT NULL, what VARCHAR(40) NOT NULL, was VARCHAR(4000) NOT NULL, now VARCHAR(4000) NOT NULL, createdBy VARCHAR(100) NOT NULL, updatedBy VARCHAR(100) NOT NULL,  createTime DATETIME NOT NULL, updateTime DATETIME NOT NULL, UNIQUE(service, id, version, boxnum, type, what, createTime, updateTime))"
                		cursor.execute(query)
                		conn.commit()
		print("Table created!!!")

	def sqlDataInput(self, service, id, version, box, type, what, was, now, createdBy, updatedBy, createTime, updateTime):
		with closing(pymysql.connect(
			host= self.host,
                        user= self.user,
                        password= self.password,
                        db= self.db,
                        charset='utf8mb4',
                        cursorclass=DictCursor
			)) as conn:
				with conn.cursor() as cursor:
					query = 'INSERT INTO control (cluster, service, id, version, boxnum, type, what, was, now, createdBy, updatedBy, createTime, updateTime) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
					cursor.execute(query, (self.cluster, service, id, version, box, type, what, was, now, createdBy, updatedBy, createTime, updateTime))
					conn.commit()


class RangerAPI(object):

	def __init__(self, cluster, ip, auth_login, auth_passwd):
		self.cluster = cluster
		self.ip = ip
		self.auth_login = auth_login
		self.auth_passwd = auth_passwd
		self.headers = {
		'Content-Type': 'application/json',
		}

	#json file methods
	def checkOriginalJson(self):
		print("Checking if original json file exists...")
		try:
			with open(self.cluster + "_" + "original.json", "r") as read_file:
				originaldata = json.load(read_file)
			with open(self.cluster + "_" + "original(data).json", "r") as read_file:
				originaldata1 = json.load(read_file)
			print("Original files already exists, that's good, parsing new data...")
			k = self.parsingIDS(True)
			self.parsingRules(k, True)
			print("Data was sucsessful parsed, let's check for some updates of policyis...")
			self.testingForUpdates()
		except IOError as e:
			print("No original rules json file")
			print("Parsing original data...")
			k = self.parsingIDS(False)
			self.parsingRules(k, False)
			print("Reboot script later to view some changes in Ranger policy...")
			print("Bye")
		return()

	def testingForUpdates(self):
		policyChange = ""
		with open(self.cluster + "_" + "original.json", "r") as read_file:
			originaldata = json.load(read_file)
		with open(self.cluster + "_" + "original(data).json", "r") as read_file:
			originaldata1 = json.load(read_file)
		with open(self.cluster + "_" + "new.json", "r") as read_file:
			newdata = json.load(read_file)
		with open(self.cluster + "_" + "new(data).json", "r") as read_file:
			newdata1 = json.load(read_file)
		if originaldata == newdata:
			print("No updates for today.")
		else:
			#if something was changed
			m = jt.diff(originaldata, newdata)
			k = len(m)
			i = 0
			#checking each difference in json files
			while i < k:
				s = list(m[i])
				iChange = False
				#if something was added
				if s[0] == "add":
					print("Something was added")
					type = s[0]
					jsonPATH = m[i][s[0]].split("/")
					#if only user or group was added in policy box
					if len(jsonPATH) == 6 and (jsonPATH[4]=="users" or jsonPATH[4]=="groups"):
						i = self.AddnewUserOrGroup(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)

					#if new policy box added
					if len(jsonPATH) > 2 and len(jsonPATH) <= 4 and jsonPATH[2]=="policyItems":
						 self.AddnewPolicybox(m, i, s, type, jsonPATH, originaldata, newdata1)

					#if new policy was added
					if len(jsonPATH) == 2:
						originaldata, originaldata1, newdata1, m, k, iChange = self.AddnewPolicy(m, i, s, type, jsonPATH, originaldata, newdata1, originaldata1, newdata, k)

					#if new policy rule was added
					if len(jsonPATH) == 6 and jsonPATH[4] == "accesses":
						i = self.AddnewPolicyRule(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)

					#if new path or queue or database was added
					if (len(jsonPATH) == 6 or len(jsonPATH) == 4) and jsonPATH[2] == "resources":
						i = self.AddnewDatabasePathQueue(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)

				#if something was removed
				if s[0] == "remove":
					print("Something was really removed!!!")
					allRules = ""
					type = "remove"
					user = ""
					allboxes = ""
					groups = ""
					jsonPATH = m[i][s[0]].split("/")
					#if removed user or group in policy box
					if len(jsonPATH) == 6 and (jsonPATH[4] =="users" or jsonPATH[4] == "groups"):
						i = self.RemoveUserOrGroup(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)

					#if policy box was removed
					if len(jsonPATH) == 4 and jsonPATH[2] != "resources":
						self.RemovePolicyBox(m, i, s, type, jsonPATH, originaldata, newdata1)

					#if policy was removed:
					if len(jsonPATH) == 2:
						originaldata, originaldata1, newdata1, m, k, iChange = self.RemovePolicy(m, i, s, type, jsonPATH, originaldata, newdata1, originaldata1, newdata, k)

					#if some rule in policy box was removed
					if len(jsonPATH) == 6 and jsonPATH[4] == "accesses":
						i = self.RemoveRulePolicyBox(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)

					#if  path or queue or database was removed
					if (len(jsonPATH) == 6 or len(jsonPATH) == 4) and jsonPATH[2] == "resources":
						i = self.RemoveDatabasePathQueue(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)

				#if something was replaced (in 08.08.19 update this type was renamed to CHANGE)
				if s[0] == "replace":
					jsonPATH = m[i][s[0]].split("/")
					what = jsonPATH[2]
					type = s[0]
					#if replaced the version of policy
					if what == "version":
						self.ReplaceVersion(m, i, s, type, jsonPATH, originaldata, newdata1)

					#if replaced policy
					if what == "id":
						originaldata, originaldata1, newdata1, m, k, iChange = self.ReplacePolicy(m, i, s, type, jsonPATH, originaldata, newdata1, originaldata1, newdata, k)

					#if some rule in policy box was replaced
					if what == "policyItems":
						#if replaced users or groups in policyBoxes
						if jsonPATH[4] == "users" or jsonPATH[4] == "groups":
							i = self.ReplaceUserOrGroup(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)

						#if some rule in policy box was replaced
						if jsonPATH[4] == "accesses":
							i = self.ReplaceRuleInPolicyBox(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)

						#if DelegateAdmin was changed:
						if jsonPATH[4] == "delegateAdmin":
							self.ReplaceDeligateAdmin(m, i, s, type, jsonPATH, originaldata, newdata1)

					#if replaced path or queue or database(column, table, url, udf)
					if what == "resources":
						i = self.ReplacePathQueueDB(m, i, s, type, jsonPATH, originaldata, newdata1, newdata)
				if iChange == False:
					i+=1
				#else:
				#	if i > 0:
				#		i = i -1
		print("Changes ended")
		return()

	#if new policy box added
	def AddnewPolicybox(self, m, i, s, type, jsonPATH, originaldata, newdata1):
		allRules = ""
		allboxes = ""
		user = ""
		groups = ""
		was = "-"
		now = "-"
		id = originaldata[int(jsonPATH[1])]["id"]
		what = jsonPATH[2]
		value = m[i][s[1]]
		h = list(value.keys())
		delegateAdmin = str(m[i]["value"][h[4]])
		box = int(jsonPATH[3]) + 1
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		for j in m[i]["value"][h[1]]:
			user += str(j) + " "
		for j in m[i]["value"][h[2]]:
			groups += str(j) + " "
		for j in m[i]["value"][h[0]]:
			allRules += str(j["type"]) + " "
		allboxes += "Users: " + user + ", groups: " + groups + ", rules: " + allRules + ", delegateAdmin : " + delegateAdmin + ". "
		now = allboxes
		print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + what + ", type: " + type + ". Num of policy box: " + str(box)  + ", was: " + was + ", now: " + now +  ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)

	#if new policy was added
	def AddnewPolicy(self, m, i, s, type, jsonPATH, originaldata, newdata1, originaldata1, newdata, k):
		allRules = ""
		now = "-"
		was = "-"
		box = "-"
		user = ""
		groups = ""
		allboxes = ""
		id = m[i][s[1]]["id"]
		version = m[i][s[1]]["version"]
		service = m[i][s[1]]["service"]
		path = str(m[i][s[1]]["resources"])
		wasId = id
		what = "policy"
		policyBoxes = m[i][s[1]]["policyItems"]
		for mr in policyBoxes:
			for j in mr["users"]:
				user += str(j) + " "
			for j in mr["accesses"]:
				allRules += str(j["type"]) + " "
			for j in mr["groups"]:
				groups += str(j) + " "
			delegateAdmin = str(mr["delegateAdmin"])
			allboxes += "Users: " + user + ", groups: " + groups + ", rules: " + allRules + ", delegateAdmin : " + delegateAdmin + ". "
			user = ""
			groups = ""
			allRules = ""
			delegateAdmin = ""
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		now = allboxes
		now += "Resources: " + str(path)
		print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + what + ", type :" + str(type) + ", was: " + was + ", now: " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		iChange = True
		for j in range(len(newdata)):
			if newdata[j]["id"] == wasId:
				newdata.pop(j)
				break
		for j in range(len(originaldata1)):
			try:
				if originaldata1[j]["policyID"] == wasId:
					originaldata1.pop(j+1)
					originaldata1.pop(j)
					break
			except KeyError:
				pass
		for j in range(len(newdata1)):
			try:
				if newdata1[j]["policyID"] == wasId:
					newdata1.pop(j+1)
					newdata1.pop(j)
					break
			except KeyError:
				pass
		m = jt.diff(originaldata, newdata)
		k = len(m)
		return(originaldata, originaldata1, newdata1, m, k, iChange)

	#if new policy rule was added
	def AddnewPolicyRule(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		what = str(jsonPATH[2]) + ":" + str(jsonPATH[4])
		id = originaldata[int(jsonPATH[1])]["id"]
		box = int(jsonPATH[3]) + 1
		value = m[i][s[1]]["type"]
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "replace" or s2[0] == "remove":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1 
			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				was2.append(reallywas["type"])
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				now2.append(reallywas["type"])
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			allboxes = "-"
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			was = "-"
			allboxes = str(value)
			now = allboxes
			print("Cluster: " + self.cluster + ". Policy ID: " + str(id) + ", Policy box: " + str(box) + ", type: " + type +  ", what: " + what + ", was: " + was + ", now: " + now +  ", createdBy: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)


	#if new user or group was added
	def AddnewUserOrGroup(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		allboxes = "-"
		was = "-"
		now = "-"
		value = str(m[i][s[1]])
		id = originaldata[int(jsonPATH[1])]["id"]
		what = str(jsonPATH[2] + ":" +  jsonPATH[4])
		now = value
		box = int(jsonPATH[3]) + 1
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "replace" or s2[0] == "remove" or s2[0] == "add":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1
			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				was2.append(reallywas)
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				now2.append(reallywas)
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", policyBox: " + str(box) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			allboxes = str(value)
			was = "-"
			now = allboxes
			print("Cluster: " + self.cluster + ". Policy ID: " + str(id) + ", Policy box: " + str(box) + ", type: " + type +  ", what: " + what + " , was: " + was + ", now: " + now +  ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)


	#Add new Path or Queue or Database(table, column, udf):
	def AddnewDatabasePathQueue(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		type = s[0]
		what2 = jsonPATH[3]
		id = originaldata[int(jsonPATH[1])]["id"]
		value = str(m[i]["value"])
		box = "-"
		what = jsonPATH[2] + ":" + jsonPATH[3]
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "remove" or s2[0] == "add" or s2[0] == "replace":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1
			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][jsonPATH[3]][jsonPATH[4]]:
				was2.append(reallywas)
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][jsonPATH[3]][jsonPATH[4]]:
				now2.append(reallywas)
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			allboxes = "-"
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			was = "-"
			now = str(value)
			print("Cluster: " + self.cluster + ". Policy ID: " + str(id) + ", type: " + type +  ", what: " + what + ", was: " + was + ", now: " + now + ", createdBy: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)

	#remove user or group in policy box
	def RemoveUserOrGroup(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		what = str(jsonPATH[2])
		prev = m[i][s[1]]
		what2 = str(jsonPATH[4])
		what = what + ":" + what2
		id = originaldata[int(jsonPATH[1])]["id"]
		box = int(jsonPATH[3]) + 1
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "replace" or s2[0] == "add" or s2[0] == "remove":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1
			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				was2.append(reallywas)
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				now2.append(reallywas)
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			allboxes = "-"
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			allboxes = str(prev)
			was = allboxes
			now = "-"
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) +  ", policy box: " + str(box) + ", type: " + type + ", was: " + was + ", now: " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)


	#if removed policy box
	def RemovePolicyBox(self, m, i, s, type, jsonPATH, originaldata, newdata1):
		what = jsonPATH[2]
		prev = m[i][s[1]]
		changes = list(m[i][s[1]].keys())
		id = originaldata[int(jsonPATH[1])]["id"]
		allboxes = ""
		allRules = ""
		user = ""
		groups = ""
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		for j in prev["accesses"]:
			allRules += str(j["type"]) + " "
		for j in prev["users"]:
			user += str(j) + " "
		for j in prev["groups"]:
			groups += str(j) + " "
		delegateAdmin = str(m[i][s[1]]["delegateAdmin"])
		allboxes += "Users: " + user + ", groups: " + groups + ", rules: " + allRules + ", delegateAdmin : " + delegateAdmin + ". "
		box = "-"
		was = allboxes
		now = "-"
		print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: policy " + what + ", type :" + type + ", was:  " + was + ", now: " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)


	#if removed policy
	def RemovePolicy(self, m, i, s, type, jsonPATH, originaldata, newdata1, originaldata1, newdata, k):
		falsepositive = False
		for j in m:
			s3 = list(j)
			jsonPATH3 = j[s3[0]].split("/")
			if len(jsonPATH3) == 3 and s3[0] == "replace" and jsonPATH3[2] == "id" and int(jsonPATH3[1]) < int(jsonPATH[1]) and j[s3[1]] == m[i][s[1]]["id"]:
				print("False positive remove of policy detected...")
				falsepositive = True
				iChange = False
				break
		if falsepositive == False:
			allRules = ""
			user = ""
			groups = ""
			allboxes = ""
			id = m[i][s[1]]["id"]
			version = m[i][s[1]]["version"]
			service = m[i][s[1]]["service"]
			nameOfPolicy = m[i][s[1]]["name"]
			path = str(m[i][s[1]]["resources"])
			what = "policy"
			wasId = id
			policyBoxes = m[i][s[1]]["policyItems"]
			for mr in policyBoxes:
				for j in mr["users"]:
					user += str(j) + " "
				for j in mr["accesses"]:
					allRules += str(j["type"]) + " "
				for j in mr["groups"]:
					groups += str(j) + " "
				delegateAdmin = str(mr["delegateAdmin"])
				allboxes += "Users: " + user + ", groups: " + groups + ", rules: " + allRules + ", delegateAdmin : " + delegateAdmin + ". "
				user = ""
				groups = ""
				allRules = ""
				delegateAdmin = ""
			was = str(allboxes) + "Resources: " + str(path)
			now = "-"
			ts = time.time()
			updateTime = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
			for j in originaldata1:
				try:
					if j["id"] == id:
						createdBy = j["createdBy"]
						createTime = j["createTime"]
						result_s = pandas.to_datetime(createTime, unit='ms')
						createTime = str(result_s)
				except KeyError:
					pass
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + what + ", type :" + str(type) + ", was: " + was + ", now: " + now + ", created by: " + createdBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
			updatedBy = "-"
			box = "-"
			local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
			for j in range(len(originaldata)):
				if originaldata[j]["id"] == wasId:
					originaldata.pop(j)
					break
			for j in range(len(originaldata1)):
				try:
					if originaldata1[j]["policyID"] == wasId:
						originaldata1.pop(j+1)
						originaldata1.pop(j)
						break
				except KeyError:
					pass
			for j in range(len(newdata1)):
				try:
					if newdata1[j]["policyID"] == wasId:
						newdata1.pop(j+1)
						newdata1.pop(j)
						break
				except KeyError:
					pass
			m = jt.diff(originaldata, newdata)
			k = len(m)
			iChange = True
		return(originaldata, originaldata1, newdata1, m, k, iChange)

	#if some rule in policy box was removed
	def RemoveRulePolicyBox(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		type = "remove"
		prev = m[i][s[1]]["type"]
		what = str(jsonPATH[2]) + ":" + str(jsonPATH[4])
		id = originaldata[int(jsonPATH[1])]["id"]
		box = int(jsonPATH[3]) + 1
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "replace" or s2[0] == "add" or s2[0] == "remove":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1
			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				was2.append(reallywas["type"])
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				now2.append(reallywas["type"])
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			was = str(prev)
			now = "-"
			print("Cluster: " + self.cluster + ". Policy ID: " + str(id) + ", Policy box: " + str(box) + ", type: " + type +  ", what: " + what + ", was: " + was + ", now: " + now + ", createdBy: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)

	#if path database or queue was removed
	def RemoveDatabasePathQueue(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		type = s[0]
		what2 = jsonPATH[3]
		id = originaldata[int(jsonPATH[1])]["id"]
		prev = str(m[i]["prev"])
		value = "-"
		box = "-"
		what = jsonPATH[2] + ":" + jsonPATH[3]
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "remove" or s2[0] == "add" or s2[0] == "replace":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1
			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][jsonPATH[3]][jsonPATH[4]]:
				was2.append(reallywas)
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][jsonPATH[3]][jsonPATH[4]]:
				now2.append(reallywas)
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			allboxes = "-"
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			was = str(prev)
			now = "-"
			print("Cluster: " + self.cluster + ". Policy ID: " + str(id) +  ", type: " + type +  ", what: " + what + " was: " + was + " now: " + now + ", createdBy: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)

	#if replaced version of policy
	def ReplaceVersion(self, m, i, s, type, jsonPATH, originaldata, newdata1):
		type = s[0]
		prev = m[i]["prev"]
		value = m[i]["value"]
		what = jsonPATH[2]
		id = originaldata[int(jsonPATH[1])]["id"]
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		type = "change"
		print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: policy " + what + ", type :" + type + ", was: " + str(prev) + ", now : " + str(value) + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		was = str(prev)
		now = str(value)
		box = "-"
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)


	#if replaced rules in policybox
	def ReplaceRuleInPolicyBox(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		prev = m[i]["prev"]
		value = m[i]["value"]
		what = jsonPATH[2] + ":" + jsonPATH[4]
		box = int(jsonPATH[3]) + 1
		id = originaldata[int(jsonPATH[1])]["id"]
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "remove" or s2[0] == "add" or s2[0] == "replace":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1

			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				was2.append(reallywas["type"])
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				now2.append(reallywas["type"])
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			was = str(prev)
			type = "change"
			now = str(value)
			print("Cluster: " + self.cluster + ". Policy ID: " + str(id) + ", Policy box: " + str(box) + ", type: " + type +  ", what: " + what + ", was: " + was + ", now: " + now  + ", createdBy: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)


	#if replaced deligateAdmin
	def ReplaceDeligateAdmin(self, m, i, s, type, jsonPATH, originaldata, newdata1):
		type = s[0]
		what = jsonPATH[4]
		id = originaldata[int(jsonPATH[1])]["id"]
		prev = str(m[i]["prev"])
		value = str(m[i]["value"])
		box = str(int(jsonPATH[3]) + 1)
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", policy box: " + box + ", what: policy " + str(what) + ", type :" + type + ", was: " + str(prev) + ", now : " + str(value)+ ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		was = str(prev)
		now = str(value)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)


	#if replaced path or queue or database
	def ReplacePathQueueDB(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		#if jsonPATH[3] == "queue" or jsonPATH[3] == "path":
		type = s[0]
		what2 = jsonPATH[3]
		id = originaldata[int(jsonPATH[1])]["id"]
		prev = str(m[i]["prev"])
		value = str(m[i]["value"])
		box = "-"
		what = jsonPATH[2] + ":" + jsonPATH[3]
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "remove" or s2[0] == "add" or s2[0] == "replace":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1
			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][jsonPATH[3]][jsonPATH[4]]:
				was2.append(reallywas)
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][jsonPATH[3]][jsonPATH[4]]:
				now2.append(reallywas)
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			was = str(prev)
			now = str(value)
			type = "change"
			print("Cluster: " + self.cluster + ". Policy ID: " + str(id) + ", Policy box: " + str(box) + ", type: " + type +  ", what: " + what + ", was: " + was + ", now: " + now  + ", createdBy: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)

	#if replace user or group in policyBox
	def ReplaceUserOrGroup(self, m, i, s, type, jsonPATH, originaldata, newdata1, newdata):
		prev = m[i]["prev"]
		value = m[i]["value"]
		id = originaldata[int(jsonPATH[1])]["id"]
		what = jsonPATH[2] + ":" + jsonPATH[4]
		box = int(jsonPATH[3]) + 1
		for j in newdata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					updatedBy = j["updatedBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					updateTime = j["updateTime"]
					result_s = pandas.to_datetime(updateTime, unit='ms')
					updateTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		#checking if is some more same policy changes
		newI = i + 1
		k = len(m)
		while newI < k:
			s2 = list(m[newI])
			jsonPATH2 = m[newI][s2[0]].split("/")
			if jsonPATH[0:5] == jsonPATH2[0:5]:
				if s2[0] == "remove" or s2[0] == "add" or s2[0] == "replace":
					type = "change"
				newI += 1
				if newI == k:
					i = k - 1
			else:
				i = newI - 1
				newI = k
		if type == "change":
			was = ""
			now = ""
			was2 = []
			now2 = []
			for reallywas in originaldata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				was2.append(reallywas)
			for reallywas in newdata[int(jsonPATH[1])][jsonPATH[2]][int(jsonPATH[3])][jsonPATH[4]]:
				now2.append(reallywas)
			for lk in now2:
				now += str(lk) + " "
			for lk in was2:
				was += str(lk) + " "
			print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + str(what) + ", type: " + type + ", was: " + was + ", now : " + now + ", created by: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		else:
			was = str(prev)
			now = str(value)
			type = "change"
			print("Cluster: " + self.cluster + ". Policy ID: " + str(id) + ", Policy box: " + str(box) + ", type: " + type +  ", what: " + what + ", was: " + was + ", now: " + now  + ", createdBy: " + createdBy + ", updatedBy: " + updatedBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service) 
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		return(i)


	#if replaced policy
	def ReplacePolicy(self, m, i, s, type, jsonPATH, originaldata, newdata1, originaldata1, newdata, k):
		wasId = m[i]["prev"]
		nowId = m[i]["value"]
		type = "remove"
		what = "policy"
		allRules = ""
		user = ""
		groups = ""
		allboxes = ""
		id = wasId
		for j in originaldata1:
			try:
				if j["id"] == id:
					createdBy = j["createdBy"]
					createTime = j["createTime"]
					result_s = pandas.to_datetime(createTime, unit='ms')
					createTime = str(result_s)
					version = j["version"]
					service = j["service"]
			except KeyError:
				pass
		ts = time.time()
		updateTime = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		policyBoxes = originaldata[int(jsonPATH[1])]["policyItems"]
		nameOfPolicy = originaldata[int(jsonPATH[1])]["name"]
		path = str(originaldata[int(jsonPATH[1])]["resources"])
		for mr in policyBoxes:
			for j in mr["users"]:
				user += str(j) + " "
			for j in mr["accesses"]:
				allRules += str(j["type"]) + " "
			for j in mr["groups"]:
				groups += str(j) + " "
			delegateAdmin = str(mr["delegateAdmin"])
			allboxes += "Users: " + user + ", groups: " + groups + ", rules: " + allRules + ", delegateAdmin : " + delegateAdmin + ". "
			user = ""
			groups = ""
			allRules = ""
			delegateAdmin = ""
		was = allboxes + "Resources: " + str(path)
		now = "-"
		print("Cluster: " + self.cluster + ", PolicyID: " + str(id) + ", what: " + what + ", type :" + str(type) + ", was: " + was + ", now: " + now + ", created by: " + createdBy + ", create time: " + createTime + ", update time: " + updateTime + ", version: " + str(version) + ", service: " + service)
		updatedBy = "-"
		box = "-"
		local.sqlDataInput(service, str(id), str(version), str(box), type, what, was, now, createdBy, updatedBy, createTime, updateTime)
		for j in range(len(originaldata)):
			if originaldata[j]["id"] == wasId:
				originaldata.pop(j)
				break
		for j in range(len(originaldata1)):
			try:
				if originaldata1[j]["policyID"] == wasId:
					originaldata1.pop(j+1)
					originaldata1.pop(j)
					break
			except KeyError:
				pass
		for j in range(len(newdata1)):
			try:
				if newdata1[j]["policyID"] == wasId:
					newdata1.pop(j+1)
					newdata1.pop(j)
					break
			except KeyError:
				pass
		m = jt.diff(originaldata, newdata)
		k = len(m)
		iChange = True
		i2 = 0
		for j in m:
			s = list(j)
			jsonPATH = j[s[0]].split("/")
			type = s[0]
			if s[0] == "add" and len(jsonPATH) == 2:
				originaldata, originaldata1, newdata1, m, k, iChange = self.AddnewPolicy(m, i2, s, type, jsonPATH, originaldata, newdata1, originaldata1, newdata)
			i2 += 1
		return(originaldata, originaldata1, newdata1, m, k, iChange)

	#parsing data methods
	def parsingIDS(self, exists):
		params = (
    			('startIndex', '0'),
		)
		response = requests.get('http://' + self.ip + '/service/public/v2/api/policy', headers=self.headers, params=params, auth=(self.auth_login, self.auth_passwd))
		data = json.loads(response.text)
		for l in data:
			k = l["id"]
		if exists == False:
			with open(self.cluster + "_" + "original.json", "w") as write_file:
    				json.dump(data, write_file)
		else:
			with open(self.cluster + "_" + "new.json", "w") as write_file:
				json.dump(data, write_file)
		return(k)

	def parsingRules(self, k, exists):
		allPolicyData = []
		i = 2
		while i <= k:
			response = requests.get('http://' + self.ip + '/service/public/v2/api/policy/' + str(i) , headers=self.headers, auth=(self.auth_login, self.auth_passwd))
			data = json.loads(response.text)
			allPolicyData += ({"policyID" : i}, data)
			i+=1
		if exists == False:
			with open(self.cluster + "_" + "original(data).json", "w") as write_file:
				json.dump(allPolicyData, write_file)
		else:
			with open(self.cluster + "_" + "new(data).json", "w") as write_file:
				json.dump(allPolicyData, write_file)


local = DatabaseOP('name_of_cluster', 'ip_of_database', 'database_admin_login', 'database_admin_password', 'name_of_database')
local2 = RangerAPI('name_of_cluster', 'ip_of_ranger',  'admin_login_of_ranger', 'admin_password_of_ranger')
local.checkDB()
local2.checkOriginalJson()
