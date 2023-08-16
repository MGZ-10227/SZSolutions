import pandas
import time
import sys
import re
import os
import argparse

logo='''
 _______  ________  _  _______        _  ____  _____
|_____  ||  ____  || ||_____  |      | ||__  ||___  |
      | || |    | || |      | |      | | _ | | _  | |
      | || |    | ||_|      | |      | || || || | | |
      | || |    | |         | |      | || ||_|| | |_|
      | || |____| |         | |_____ |_|| |__ | |_________
      |_||________|         |_______|   |____||___________| Threat Identification and Analysis
'''
second_engine_separator = '/,'

class LoopholeRule(object):
	def __init__(self):
		self.loophole_name = None
		self.loophole_regular = None
		self.hit_counts = 0
		
	def Initialization(self, loophole_name, loophole_regular):
		self.loophole_name = loophole_name
		self.loophole_regular = re.compile(str(loophole_regular))

	def Getit(self):
		self.hit_counts += 1


class OneRule(object):
	def __init__(self):
		self.threat_type = None
		self.priority = 0
		self.first_engine = None
		self.second_engine = []
		self.third_engine = []

		self.depth = 0
		self.loophole_counts = 0
		self.lonely_loophole_name = None

		self.hit_counts = 0
		#self.hits = None
		#self.hits = pandas.DataFrame(columns=label)

		self.first_confidence = 2
		self.second_confidence = 1
		self.third_confidence = 1

	def SayOne(self, threat_type, priority, first_engine):
		self.threat_type = threat_type
		self.priority = priority
		self.first_engine = re.compile(first_engine)
		self.depth += 1

	def SayTwo(self, second_engine):
		if second_engine_separator in second_engine:
			for i in second_engine.split(second_engine_separator):
				self.second_engine.append(re.compile(i))
		else:
			self.second_engine.append(re.compile(second_engine))
		self.depth += 1

	def SayThree(self, loophole_name, loophole_regular):
		self.AddLoopholeRule(loophole_name, loophole_regular)
		self.depth += 1

	def SayLonely(self, loophole_name):
		self.lonely_loophole_name = loophole_name

	def AddLoopholeRule(self, loophole_name, loophole_regular):
		loophole = LoopholeRule()
		loophole.Initialization(loophole_name, loophole_regular)
		self.third_engine.append(loophole)
		self.loophole_counts += 1

	def Getit(self):
		self.hit_counts += 1

	def __lt__(self, other):
		return self.priority < other.priority

	def SayOh(self, arg):
		if self.first_engine.search(arg):
			comeing = {
				'威胁类型': None,
				'关键字': [],
				'攻击利用漏洞': None,
				'置信度': 0,
			}
			comeing['威胁类型'] = self.threat_type
			comeing['关键字'].append(self.first_engine.pattern)
			comeing['置信度'] += self.first_confidence
			self.Getit()
			if len(self.second_engine) == 0:
				if len(self.third_engine) == 0:
					comeing['攻击利用漏洞'] = self.lonely_loophole_name
				else:
					for t in self.third_engine:
						if t.loophole_regular.search(arg):
							comeing['关键字'].append(t.loophole_regular.pattern)
							comeing['攻击利用漏洞'] = t.loophole_name
							comeing['置信度'] += self.third_confidence
							t.Getit()
							break
			else:
				for s in self.second_engine:
					if s.search(arg):
						comeing['关键字'].append(s.pattern)
						comeing['置信度'] += self.second_confidence
				if len(self.third_engine) == 0:
					comeing['攻击利用漏洞'] = self.lonely_loophole_name
	
				else:
					for t in self.third_engine:
						if t.loophole_regular.search(arg):
							comeing['关键字'].append(t.loophole_regular.pattern)
							comeing['攻击利用漏洞'] = t.loophole_name
							comeing['置信度'] += self.third_confidence
							t.Getit()
							break
			return comeing
		else:
			return None


class PickBitch(object):
	def __init__(self, config):
		self.configname = config
		self.InitializeRule(self.configname)
		self.InitializeNameSpace(self.configname)
		self.InitializeBadKids(self.configname)
		self.InitializeWhiteSilk(self.configname)

	def InitializeRule(self, config):
		print("正在初始化引擎-------------")
		self.rules = []
		self.pd_ruleconfig = self.PandasReadXlsx(config, _sheet_name = 'RuleEngine')
		for index,row in self.pd_ruleconfig.iterrows():
			if pandas.isna(row['一级引擎']) == False:
				one = OneRule()
				if pandas.isna(row['威胁类型']):
					one.SayOne(self.rules[-1].threat_type,int(row['一级引擎优先级']),row['一级引擎'])
				else:
					one.SayOne(row['威胁类型'],int(row['一级引擎优先级']),row['一级引擎'])
				if pandas.isna(row['二级引擎']) == False:
					one.SayTwo(row['二级引擎'])
				if pandas.isna(row['三级引擎']):
					if pandas.isna(row['攻击利用漏洞']) == False:
						one.SayLonely(row['攻击利用漏洞'])
				else:
					if pandas.isna(row['攻击利用漏洞']):
						print("该三级引擎未配置利用漏洞名称------------\n",row['威胁类型'],row['三级引擎'])
						one.SayThree('未配置漏洞名', row['三级引擎'])
					else:
						one.SayThree(row['攻击利用漏洞'],row['三级引擎'])
				self.rules.append(one)
			else:
				if pandas.isna(row['三级引擎']) == False:
					if pandas.isna(row['攻击利用漏洞']):
						print("该三级引擎未配置利用漏洞名称------------\n",row['三级引擎'])
						self.rules[-1].AddLoopholeRule('未配置漏洞名', row['三级引擎'])
					else:
						self.rules[-1].AddLoopholeRule(row['攻击利用漏洞'],row['三级引擎'])					 
		if len(self.rules) == 0:
			print("引擎初始化失败！------------")
			sys.exit()
		else:
			for i in self.rules:
				if i.lonely_loophole_name and len(i.third_engine):
					print("该条规则格式错乱，请检查config文件，------------\n[error]>>",i.__dict__)
					sys.exit()
		self.rules.sort(key=lambda a: a.priority)

	def InitializeNameSpace(self, config):
		self.pd_namespace = self.PandasReadXlsx(config, _sheet_name = 'NameSpace')
		self.pd_namespace.set_index('file_type', inplace = True)
	
	def InitializeBadKids(self, config):
		self.badkids = self.PandasReadXlsx(config, _sheet_name = 'BadKids')
		#

	def InitializeWhiteSilk(self, config):
		self.whitesilk = self.PandasReadXlsx(config, _sheet_name = 'WhiteSilk')
		self.shapely = pandas.DataFrame()

	def InitializeBitchsDict(self):
		self.bitchs = {}
		for i in self.pd_ruleconfig['威胁类型'].dropna().unique().tolist():
			self.bitchs.update({i:[]})

	def PandasReadCSV(self, filename, _encoding='ANSI'):
		try:
			return pandas.read_csv(filename, encoding=_encoding)
		except Exception as e:
			print("读取csv文件失败------------\n[error]>>",e)
			sys.exit()

	def PandasReadXlsx(self, filename, _encoding='ANSI', _sheet_name=None):
		if _sheet_name:
			try:
				return pandas.read_excel(filename, encoding= _encoding, sheet_name=_sheet_name)
			except Exception as e:
				print("读取xlsx文件失败------------\n[error]>>",e)
				sys.exit()
		else:
			try:
				return pandas.read_excel(filename, encoding= _encoding)
			except Exception as e:
				print("读取xlsx文件失败------------\n[error]>>",e)
				sys.exit()

	def PandasRepeatSort(self, key, baby):
		if len(baby):
			counts = baby[key].value_counts()
			sort_list = list(counts.index)
			baby[key] = baby[key].astype('category')
			baby[key].cat.set_categories(sort_list, inplace=True)
			baby.sort_values(key, ascending=True, inplace=True)

	def ComeOnMasseur(self, inspectfile, _encoding):
		tails = os.path.splitext(inspectfile)[1]
		if tails == '.xlsx' or tails == '.xls':
			self.girls = self.PandasReadXlsx(inspectfile, _encoding)
		elif tails == '.csv':
			self.girls = self.PandasReadCSV(inspectfile, _encoding)
		else:
			print('文件类型不支持------------')
			sys.exit()

	def Interview(self, antecedents, pants):
		self.antecedents = antecedents
		self.pants = pants
		if self.antecedents in self.pd_namespace.index:
			ant = self.pd_namespace.loc[self.antecedents,:].dropna()
			if set(ant) <= set(self.girls.columns.values):
				self.girls =  self.girls.loc[:,list(ant)]
				self.gspot = self.pd_namespace.loc[self.antecedents,'payload']
			else:
				print('指定模式必要字段名：',self.antecedents,set(ant))
				print('读取文件字段名：',set(self.girls.columns.values))
				print('受检文件中缺少必要字段------------')
				sys.exit()
			if self.pants in self.pd_namespace.index:
				if set(ant) > set(self.pd_namespace.loc[self.pants,:]):
					print('输出文档存在字段未指定------------')
					print(self.pants)
					print('下次吧------------')
					sys.exit()	
			else:
				print('输出文档未指定------------')
				print(self.pants)
				print('下次吧------------')
				sys.exit()		
		else:
			print('此功能还没写，宝------------')
			print(self.antecedents)
			print('下次吧------------')
			sys.exit()	

	def FreshLover(self):
		self.InitializeBitchsDict()
		for rule in self.rules:
			boys = []
			bar = Processbar(len(self.girls), granularity = 52)
			print('-----------------------------')
			self.girls.reset_index(drop = True, inplace = True)
			for index,row in self.girls.iterrows():
				bar.Fresh(index, text = '正在检查{' + str(rule.threat_type) + '}第' + str(index+1) + '行|')
				r = rule.SayOh(str(row[self.gspot]))
				if r:
					#bar.Tips('  入库：' + str(r['关键字']))
					boy = {}
					for c,l in self.pd_namespace.iteritems():
						if pandas.isna(l[self.antecedents]):
							boy.update({l[self.pants]:None})
						else:
							boy.update({l[self.pants]:row[l[self.antecedents]]})
					boy.update(r)
					boys.append(boy)
					self.girls.drop(index, inplace = True)
			if len(boys):
				self.bitchs[rule.threat_type].extend(boys)
			bar.Newline()

	def Spanking(self):
		if len(self.badkids):
			for i,r in self.badkids.iterrows():
				self.girls = self.girls[~self.girls[self.pd_namespace.loc[self.pants,'enent_name']].isin([r['enent_name']])]
	
	def TalentShow(self, key, girls, Passerby=True):
		if len(self.whitesilk):
			for i,r in self.whitesilk.iterrows():
				g = girls[girls[key]==r['src_ip']]
				if len(g):
					self.shapely = pandas.concat([self.shapely,g], ignore_index=True)
					girls = girls[~girls[key].isin([r['src_ip']])]
		if Passerby:
			return girls
		else:
			return None

	def CastingCouch(self, gspot):
		self.girls['威胁类型'] = ""
		self.girls['关键字'] = ""
		self.girls['攻击利用漏洞'] = ""
		self.girls['置信度'] = ""
		bar = Processbar(len(self.girls))
		for ind, row in self.girls.iterrows():
			for rule in self.rules:
				r = rule.SayOh(str(row[gspot]))
				if r:
					#bar.Tips('  入库：' + str(r['关键字']))
					self.girls.loc[ind,'威胁类型'] = r['威胁类型']
					self.girls.loc[ind,'关键字'] = str(r['关键字'])
					self.girls.loc[ind,'攻击利用漏洞'] = r['攻击利用漏洞']
					self.girls.loc[ind,'置信度'] = r['置信度']
					break
			bar.Fresh(ind, text = '正在检查第' + str(ind+1) + '行|')
		bar.Newline()
		bar.Clear()

	def RemoveKongge(self, gspot):
		for ind, row in self.girls.iterrows():
			self.girls.loc[ind,gspot] = str(row[gspot]).replace(' ','')

	def Census(self):
		self.pd_ruleconfig['一级引擎匹配数'] = ''
		self.pd_ruleconfig['三级引擎匹配数'] = ''
		for index,row in self.pd_ruleconfig.iterrows():
			for i in self.rules:
				if pandas.isna(row['一级引擎']) == False and row['一级引擎'] == i.first_engine.pattern:
					self.pd_ruleconfig.loc[index,'一级引擎匹配数'] = i.hit_counts
					if pandas.isna(row['三级引擎']) == False:
						for t in i.third_engine:
							if row['三级引擎'] == t.loophole_regular.pattern:
								self.pd_ruleconfig.loc[index,'三级引擎匹配数'] = t.hit_counts
					else:
						self.pd_ruleconfig.loc[index,'三级引擎匹配数'] = i.hit_counts
				else:
					if pandas.isna(row['三级引擎']) == False:
						for t in i.third_engine:
							if row['三级引擎'] == t.loophole_regular.pattern:
								self.pd_ruleconfig.loc[index,'三级引擎匹配数'] = t.hit_counts
		#self.pd_ruleconfig = self.pd_ruleconfig.loc[:,['威胁类型','一级引擎匹配数','攻击利用漏洞','三级引擎匹配数']]

	def CutBangs(self):
		for c,l in self.pd_namespace.iteritems():
			if pandas.isna(l[self.antecedents]):
				self.girls[l[self.pants]] = ''
			else:
				self.girls.rename(columns={l[self.antecedents]:l[self.pants]}, inplace=True)
		self.girls = self.girls[list(self.pd_namespace.loc[self.pants,:])]
		self.PandasRepeatSort(self.pd_namespace.loc[self.pants,'src_ip'],self.girls)

	def Bastard(self, outengine='xlsxwriter'):
		if len(self.bitchs):
			print('-----------------------------')
			print("检查完毕，正在输出结果文档------------")
			if outengine == 'xlsxwriter':
				suffix = '.xlsx'
			else:
				suffix = '.xls'
			filename =self.antecedents + '-result-' + time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time())) + suffix
			self.CutBangs()
			with pandas.ExcelWriter(filename, engine=outengine) as writer:
				for k,v in self.bitchs.items():
					if v:
						r = pandas.DataFrame.from_dict(v)
						r = self.TalentShow(self.pd_namespace.loc[self.pants,'src_ip'],r)
						self.PandasRepeatSort(self.pd_namespace.loc[self.pants,'src_ip'],r)
						r.to_excel(writer, sheet_name=k, index=False, header=True, na_rep='')
				self.girls = self.TalentShow(self.pd_namespace.loc[self.pants,'src_ip'],self.girls)
				self.Spanking()
				self.girls.to_excel(writer, sheet_name='其他', index=False, header=True, na_rep='')
				self.pd_ruleconfig.to_excel(writer, sheet_name='统计', index=False, header=True, na_rep='')
				self.PandasRepeatSort(self.pd_namespace.loc[self.pants,'src_ip'],self.shapely)
				self.shapely.to_excel(writer, sheet_name='白名单', index=False, header=True, na_rep='')
			print("输出结果文档成功：" + filename)
			print("拜拜-----")
		else:
			print("结果文档为空------------")
			print("啥也没整出来------------")	
			sys.exit()	

	def Debut(self, s_ip_key, outengine='xlsxwriter'):
		print('-----------------------------')
		print("检查完毕，正在输出结果文档------------")
		if outengine == 'xlsxwriter':
			suffix = '.xlsx'
		else:
			suffix = '.xls'
		filename ='Check-result-' + time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time())) + suffix
		self.TalentShow(s_ip_key, self.girls, Passerby=False)	
		with pandas.ExcelWriter(filename, engine=outengine) as writer:
			self.girls.to_excel(writer, sheet_name='Sheet1', index=False, header=True, na_rep='')
			self.pd_ruleconfig.to_excel(writer, sheet_name='统计', index=False, header=True, na_rep='')
			if len(self.shapely):
				self.shapely.to_excel(writer, sheet_name='白名单', index=False, header=True, na_rep='')
		print("输出结果文档成功：" + filename)
		print("拜拜-----")	


class Processbar():
	def __init__(self, complete, granularity = 66):
		self.granularity = granularity
		self.complete = complete
		
	def Fresh(self, arg, text='正在办事|'):
		self.proportion = arg/self.complete	
		sys.stdout.write(text)
		sys.stdout.write("*" * round(self.proportion * self.granularity))
		sys.stdout.write(str(self.proportion)[2:4] + '%'  + '|100%' + '\r')

	def State(self, arg):
		now = str(arg/self.complete)[2:4]
		sys.stdout.write('-----------------------------')
		sys.stdout.write('正在干活：'+ now + "%")
		sys.stdout.write('第' + str(arg) +'票:')
		sys.stdout.write('\n')

	def Tips(self, arg):
		sys.stdout.write('\n')
		sys.stdout.write(arg)
		sys.stdout.write('\n')
		
	def Newline(self):
		sys.stdout.write('\n')

	def Clear(self):
		sys.stdout.flush()

			
def Pack(filename,config='Config.xlsx',antecedents='全流量', pants='监测上报单',_encoding='ANSI',isoutxls=False,remo=False):
	a=PickBitch(config)
	a.ComeOnMasseur(filename, _encoding)
	a.Interview(antecedents, pants)
	print('-----------------------------')
	print('初始化成功------------')
	if remo:
		a.RemoveKongge(a.gspot)
	a.FreshLover()
	a.Census()
	if isoutxls:
		a.Bastard(outengine='xlwt')
	else:
		a.Bastard()

def Check(filename,config='Config.xlsx',gspot='载荷',s_ip='源IP',_encoding='ANSI',isoutxls=False,remo=False):
	a=PickBitch(config)
	a.ComeOnMasseur(filename, _encoding)
	print('-----------------------------')
	print('初始化成功------------')
	if remo:
		a.RemoveKongge(gspot)
	a.CastingCouch(gspot)
	a.Census()
	if isoutxls:
		a.Debut(s_ip, outengine='xlwt')
	else:
		a.Debut(s_ip)

if __name__ == '__main__':
	print(logo)
	parser = argparse.ArgumentParser(description='老石威胁分析工具，安全运营的首选！')
	parser.add_argument('-m','--mode',metavar='mode',choices=['check','pack'],help='指定模式',required=True)
	parser.add_argument("-f","--file",metavar='file',help="指定受检文件名",required=True)
	parser.add_argument("-t","--type",metavar='type',default='全流量',help="指定受检文件类型")
	parser.add_argument("-g","--grasp",metavar='grasp',default='载荷',help="指定关键遍历字段")
	parser.add_argument("-c","--config",metavar='config',default='Config.xlsx',help="指定配置文件")
	parser.add_argument("-p","--putout",metavar='putout',default='监测上报单',help="指定输出文档类型")
	parser.add_argument("-e","--encode",metavar='encode',default='ANSI',help="指定读取文档编码")
	parser.add_argument("-s","--srcip",metavar='srcip',default='源IP',help="指定读取文档src_ip列字段名")
	parser.add_argument("-o","--outxls", action='store_true', help="以xls格式输出文档")
	parser.add_argument("-rk","--removekongge", action='store_true', help="去除关键遍历字段里空格")
	args = parser.parse_args()
	if args.mode == 'pack':
		Pack(args.file,config=args.config,antecedents=args.type,pants=args.putout,_encoding=args.encode,isoutxls=args.outxls,remo=args.removekongge)
	if args.mode == 'check':
		Check(args.file,config=args.config,gspot=args.grasp,s_ip=args.srcip,_encoding=args.encode,isoutxls=args.outxls,remo=args.removekongge)


