from datetime import datetime
import Tkinter
import ttk
import tkMessageBox
import tkFileDialog

PROGRAM_NAME = 'MMT Rule Editor'
EXPRESSION_TYPE = ['Normal', 'Embedded Function']
RULE_OPERATOR_VALUES = ['THEN','BEFORE']
EVENT_VALUES = ['COMPUTE', '????']
TYPES = ['ATTACK', 'EVASION', 'SECURITY']
UNITS = ['ms', 's']
NUM_EVENTS = [2, 3, 4]
RELATIONS = ['AND', 'OR']
COMPARISONS = ['==', '!=', '>', '<']
VALUE_TYPES = ['proto.attribute', 'Direct value']

class Expression:
	def __init__(self, window):
		self.relation = None

		self.window = window

		self.type = Tkinter.StringVar()
		self.type.set(EXPRESSION_TYPE[0])

		self.comparison = Tkinter.StringVar()
		self.comparison.set(COMPARISONS[0])

		self.protocol = ''
		self.attribute = Tkinter.StringVar()
		self.function_name = ''
		self.num_argument = Tkinter.IntVar()
		self.value = ''

	#-----------Setter Method-----------#
	def set_relation(self, relation):
		self.relation = relation

	def set_type(self, expr_type):
		self.type.set(expr_type)

	def set_protocol(self, protocol):
		self.protocol = protocol

	def set_attribute(self, attribute):
		self.attribute.set(attribute)

	def set_comparison(self, comparison):
		self.comparison.set(comparison)

	def set_function_name(self, function_name):
		self.function_name = function_name

	def set_num_argument(self, num_argument):
		self.num_argument.set(num_argument)

	def set_value(self, value):
		self.value = value
	#-----------End Setter Method-----------#

	#-----------Getter Method-----------#
	def get_relation(self):
		return self.relation

	def get_window(self):
		return self.window

	def get_type(self):
		return self.type.get()

	def get_protocol(self):
		return self.protocol

	def get_attribute(self):
		return self.attribute.get()

	def get_comparison(self):
		return self.comparison.get()

	def get_function_name(self):
		return self.function_name

	def get_num_argument(self):
		return self.num_argument.get()

	def get_value(self):
		return self.value
	#-----------End Getter Method-----------#

# Event class
class Event:
	def __init__(self, window):
		self.id = 0
		self.value = Tkinter.StringVar(window)
		self.window = window
		self.description = ''
		self.boolean_expression = ''

	#-----------Setter Method-----------#
	def set_id(self, id):
		self.id = id

	def set_description(self, description):
		self.description = description

	def set_boolean_expression(self, boolean_expression):
		self.boolean_expression = boolean_expression
	#-----------End Setter Method-----------#

	#-----------Getter Method-----------#
	def get_id(self):
		return self.id

	def get_value(self):
		return self.value.get()

	def get_description(self):
		return self.description

	def get_boolean_expression(self):
		return self.boolean_expression
	#-----------End Getter Method-----------#
	# Create the boolean expression
	def make_expression(self, expr, rel):
		expression = ''
		expression += '('
		expression += expr
		expression += ')'
		if rel != None:
			if rel == 'AND':
				expression += '&amp;&amp;'
			else:
				expression += '||'
			self.boolean_expression = '(' + expression + self.boolean_expression + ')' 
		else:
			self.boolean_expression = expression


	#-----------Validate Method-----------#

	#-----------End Validate Method-----------#
	def to_string(self, indent):
		event = indent
		event += ('<event ' + 'value="' + self.value.get() + '" ' +
				  'event_id= "' + str(self.id) + '"\n' +
				  indent + '       ' + 'description="' + self.description + '"\n' +
				  indent + '       ' + 'boolean_expression="' + self.boolean_expression + '"/>\n')
		return event


# Operator class
class Operator:
	def __init__(self, window, id):
		self.id = id
		self.value = Tkinter.StringVar(window)
		self.value.set(RULE_OPERATOR_VALUES[0])

		self.delay_unit = Tkinter.StringVar(window)
		self.delay_unit.set(UNITS[0])

		self.min_delay = ''
		self.max_delay = ''
		self.events = [None, None]

	#-----------Setter Method-----------#
	def set_min_delay(self, min_delay):
		self.min_delay = min_delay

	def set_max_delay(self, max_delay):
		self.max_delay = max_delay

	def add_created_event(self, event):
		if event.get_id() % 2 == 0:
			self.events[1] = event
		else:
			self.events[0] = event
	#-----------End Setter Method-----------#

	#-----------Getter Method-----------#
	def get_id(self):
		return self.id

	def get_value(self):
		return self.value.get()

	def get_delay_unit(self):
		return self.delay_unit.get()

	def get_min_delay(self):
		return self.min_delay

	def get_max_delay(self):
		return self.max_delay

	def get_events(sefl):
		return self.events
	#-----------End Getter Method-----------#

	def to_string(self):
		operator = '\t'
		operator += ('<operator ' + 'value="' + self.value.get() + '" ' +
					 'delay_unit="' + self.delay_unit.get() + '" ' +
					 'delay_min="' + self.max_delay + '" ' +
					 'delay_max="' + self.min_delay + '">\n')
		for event in self.events:
			operator += event.to_string('\t   ')
		operator += '\t</operator>\n'
		return operator


# Class rule
class Rule:
	def __init__(self, root):	
		self.root = root
		root.title(PROGRAM_NAME)
		self.id = 0

		self.value = Tkinter.StringVar()
		self.value.set(RULE_OPERATOR_VALUES[0])

		self.delay_unit = Tkinter.StringVar()
		self.delay_unit.set(UNITS[0])

		self.min_delay = ''
		self.max_delay = ''
		self.description = ''

		self.type = Tkinter.StringVar()
		self.type.set(TYPES[0])

		self.num_event = Tkinter.IntVar()

		self.operators = []
		self.events = []
		self.embedded_functions = []
		self.protos = {}
		self.init_rule_window()
		self.create_id()
		self.get_proto_attr_names()

	#-----------Setter method-----------#
	def set_id(self, id):
		self.id = id

	def set_value(self, value):
		self.value.set(value)

	def set_delay_unit(self, edlay_unit):
		self.delay_unit.set(delay_unit)

	def set_min_delay(self, min_delay):
		self.min_delay = min_delay

	def set_max_delay(self, max_delay):
		self.max_delay = max_delay

	def set_description(self, description):
		self.description = description

	def set_num_event(self, num_event):
		self.num_event.set(num_event)

	def set_type(self, type):
		self.type = type

	def add_created_operator(self, operator):
		self.operators[operator.get_id() - 1] = operator

	def add_created_event(self, event):
		self.events[event.get_id() - 1] = event
	#-----------End Setter method-----------#

	#-----------Getter method-----------#
	def get_id(self):
		return self.id

	def get_value():
		return self.value.get()

	def get_delay_unit():
		return self.delay_unit.get()

	def get_min_delay():
		return self.min_delay

	def get_max_delay():
		return self.max_delay

	def get_num_event(self):
		return self.num_event.get()

	def get_type():
		return self.type.get()
	#-----------End Setter method-----------#

	def to_string(self):
		xml = ''
		xml += '<beginning>\n'
		xml += ('<property ' + 'value="' + self.value.get() + '" ' +
				'delay_unit="' + self.delay_unit.get() + '" ' +
				'delay_max="' + self.max_delay + '" ' +
				'delay_min="' + self.min_delay + '" '+
				'property_id="' + str(self.id) + '" '+
				'type_property="' + self.type.get() + '"\n' +
				'\tdescription="' + self.description + '">\n')

		if self.num_event.get() == 2:
			for event in self.events:
				xml += event.to_string('\t')
		elif self.num_event.get() == 3:
			xml += self.operators[0].to_string()
			xml += self.events[2].to_string('\t')
		else:
			for operator in self.operators:
				xml += operator.to_string()

		xml += '</property>\n'
		if len(self.embedded_functions) > 0:
			xml += '<embedded_functions><![CDATA[\n'
			xml += ('static inline int em_fuct(){\n'
   				   + '//put your code here\n'
				   + '}\n'
 				   + '//This fuction is called when the rules in this file being loaded into MMT-Security\n'
 	               + '//void on_load(){\n'
 	               + '//}\n'
 	               + '//This fuction is called when exiting MMT-Security\n'
 	               + '//void on_unload(){\n'
 	               + '//})\n')
			xml += ']]></embedded_functions>\n'
		xml += '</beginning>\n'
		return xml



	# Create ID of the rule based on the precise time
	# Format of the ID Year-Month-Date-Hour-Minute-Second 
	def create_id(self):
		full = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		date = full.split(' ')[0].split('-')
		time = full.split(' ')[1].split(':')

		id = date[0] + date[1] + date[2] + time[0] + time[1] + time[2]

		self.id = id
		return id 


	# Get the list of protocols and their attributes
	def get_proto_attr_names(self):
		f = open('proto_attributes_list.txt', 'r')
		name = ''
		for line in f:
			if 'Protocol' in line:
				name = name + '|' + line.split('Name')[1].strip()
			if 'Attribute' in line:
				name = name + '-' + line.split('Name')[1][1:].strip()
		name = name[1:]
		protos = name.split('|')
		for proto in protos:
			temp = proto.split('-')
			self.protos[temp[0]] = temp[1:]
		

	#----------------------Method for GUI----------------------#
	#-----------------Main window-----------------#
	def init_rule_window(self):
		Tkinter.Label(self.root, text='ID:').grid(row=0, column=0, sticky='w')
		Tkinter.Label(self.root, text=self.create_id()).grid(row=0, column=1, padx=2, pady=2, sticky='w')

		Tkinter.Label(self.root, text='Value:').grid(row=1, column=0, sticky='w')
		rule_value_menu = Tkinter.OptionMenu(self.root, self.value, *RULE_OPERATOR_VALUES)
		rule_value_menu.config(width=5)
		rule_value_menu.grid(row=1, column=1, padx=2, pady=2, sticky='w')

		Tkinter.Label(self.root, text='Type:').grid(row=2, column=0, sticky='w')
		type_menu = Tkinter.OptionMenu(self.root, self.type, *TYPES)
		type_menu.config(width=6)
		type_menu.grid(row=2, column=1, padx=2, pady=2, sticky='w')

		Tkinter.Label(self.root, text='Delay unit:').grid(row=3, column=0, sticky='w', padx=2, pady=2)
		rule_unit_menu = Tkinter.OptionMenu(self.root, self.delay_unit, 'ms', 's')
		rule_unit_menu.config(width=1)
		rule_unit_menu.grid(row=3, column=1, padx=2, pady=2, sticky='w')

		Tkinter.Label(self.root, text='Minimum delay:').grid(row=4, column=0, sticky='w', padx=2, pady=2)
		rule_minimum_delay_text = Tkinter.Text(self.root, height=1, width=8)
		rule_minimum_delay_text.grid(row=4, column=1, padx=2, pady=2, sticky='w')
		rule_minimum_delay_text.insert('end', '0')
		rule_minimum_delay_text.bind("<Tab>", self.focus_next_entry)

		Tkinter.Label(self.root, text='Maximum delay:').grid(row=5, column=0, sticky='w', padx=2, pady=2)
		rule_maximum_delay_text = Tkinter.Text(self.root, height=1, width=8)
		rule_maximum_delay_text.grid(row=5, column=1, padx=2, pady=2, sticky='w')
		rule_maximum_delay_text.insert('end', '0')
		rule_maximum_delay_text.bind("<Tab>", self.focus_next_entry)

		Tkinter.Label(self.root, text='Description:').grid(row=6, column=0, sticky='w', padx=2, pady=2)
		rule_description_text = Tkinter.Text(self.root, height=3, width=30)
		rule_description_text.grid(row=6, column=1, padx=2, pady=2, columnspan=3, rowspan=3, sticky='we')
		rule_description_text.insert('end', 'Describe your rule')
		rule_description_text.bind("<Tab>", self.focus_next_entry)

		Tkinter.Label(self.root, text='Number of events:').grid(row=9, column=0, sticky='w', padx=2, pady=2)
		num_event_menu = Tkinter.OptionMenu(self.root, self.num_event, *NUM_EVENTS, command=lambda _: self.show_num_events_case(self.get_num_event()))
		num_event_menu.config(width=1)
		num_event_menu.grid(row=9, column=1, padx=2, pady=2, sticky='w')

		save_button = Tkinter.Button(self.root, text='Save', command=self.save_rule)
		save_button.grid(row=13, column=3, sticky='e')

	# Main window: continue
	# Show the GUI when change the number of event 
	def show_num_events_case(self, num_event):
		num_events_case_frame = self.root.grid_slaves(14, 0)
		if len(num_events_case_frame) == 0:
			self.init_num_events_case_frame(num_event)	
		else:
			num_events_case_frame[0].grid_forget()
			self.init_num_events_case_frame(num_event)

	def init_num_events_case_frame(self, num_event):
		if len(self.root.grid_slaves(13, 3)) != 0:
			save_button = self.root.grid_slaves(13, 3)[0]
			save_button.grid(row=17, column=3)

		bottom_frame = Tkinter.Frame(self.root, height=4)
		bottom_frame.grid(row=13, column=0, rowspan=3, columnspan=4, sticky='we')

		note_label = Tkinter.Label(bottom_frame, text='')
		note_label['foreground'] = 'red'
		note_label.grid(row=0, column=0, columnspan=5,sticky='we', padx=2, pady=2)

		name_1_label = Tkinter.Label(bottom_frame, text='')
		name_1_label.grid(row=1, column=0, sticky='w', padx=2, pady=2)
		name_2_label = Tkinter.Label(bottom_frame, text='')
		name_2_label.grid(row=2, column=0, sticky='w', padx=2, pady=2)

		Tkinter.Label(bottom_frame, text='                   ').grid(row=1, column=1)
		Tkinter.Label(bottom_frame, text='                   ').grid(row=2, column=1)

		status_1_label = Tkinter.Label(bottom_frame, text='Not Available')
		status_1_label.grid(row=1, column=2, sticky='w')
		status_2_label = Tkinter.Label(bottom_frame, text='Not Available')
		status_2_label.grid(row=2, column=2, sticky='w')

		Tkinter.Label(bottom_frame, text='                   ').grid(row=1, column=3)
		Tkinter.Label(bottom_frame, text='                   ').grid(row=2, column=3)

		create_button_1 = Tkinter.Button(bottom_frame, text='Create')
		create_button_1.grid(row=1, column=4, sticky='e')
		create_button_2 = Tkinter.Button(bottom_frame, text='Create')
		create_button_2.grid(row=2, column=4, sticky='e')

		if num_event == 2:
			self.events[:] = []
			self.operators[:] = []
			self.events = [None, None]
			note_label['text'] = 'You need to create 2 events'
			name_1_label['text'] = 'Event 1:'
			name_2_label['text'] = 'Event 2:'
			create_button_1.config(command=lambda: self.init_event_window(status_1_label, 1, self.root))
			create_button_2.config(command=lambda: self.init_event_window(status_2_label, 2, self.root))

		elif num_event == 3:
			self.events[:] = []
			self.operators[:] = []
			self.operators = [None]
			self.events = [None, None, None]

			note_label['text'] = 'You need to create 1 operator containing 2 events and another \n event outside'
			name_1_label['text'] = 'Operator:'
			name_2_label['text'] = 'Event:'
			create_button_1.config(command=lambda: self.init_operator_window(status_1_label, 1))
			create_button_2.config(command=lambda: self.init_event_window(status_2_label, 3, self.root))

		else:
			self.events[:] = []
			self.operators[:] = []
			self.events = [None, None, None, None]
			self.operators = [None, None]

			note_label['text'] = 'You need to create 2 operators, each contains 2 events'
			name_1_label['text'] = 'Operator 1:'
			name_2_label['text'] = 'Operator 2:'
			create_button_1.config(command=lambda: self.init_operator_window(status_1_label, 1))
			create_button_2.config(command=lambda: self.init_operator_window(status_2_label, 2))

	def focus_next_entry(self, event):
	    event.widget.tk_focusNext().focus()
	    return("break")

	def save_rule(self):
		if self.get_num_event() == 0:
			tkMessageBox.showwarning('Invalid Value', 'Number of event cannot be 0')
			return

		status_1 = self.root.grid_slaves(13, 0)[0].grid_slaves(1, 2)[0]['text']
		status_2 = self.root.grid_slaves(13, 0)[0].grid_slaves(2, 2)[0]['text']

		max_delay = self.root.grid_slaves(4, 1)[0].get('1.0', 'end-1c')
		min_delay = self.root.grid_slaves(5, 1)[0].get('1.0', 'end-1c')
		description = self.root.grid_slaves(6, 1)[0].get('1.0', 'end-1c')

		#max = 0
		#min = 0
		if len(max_delay) == 0:
			tkMessageBox.showwarning('Empty Field', 'The maximum delay field cannot be empty')
			return
		#else:
			#try:
		#		max = float(max_delay)
			#except ValueError:
			#	tkMessageBox.showwarning('Invalid Value', 'The maximum delay must be a number')
		#		return

		if len(min_delay) == 0:
			tkMessageBox.showwarning('Empty Field', 'The minimum delay field cannot be empty')
			return
		#else:
			#try:
		#		min = float(min_delay)
			#except ValueError:
			#	tkMessageBox.showwarning('Invalid Value', 'The minimum delay must be a number')
		#		return

		#if max < min:
		#	tkMessageBox.showwarning('Invalid Value', 'The minimum delay must be smaller than the maximum delay')
		#	return

		if self.get_num_event() == 2:
			if 'Not' in status_1 and 'Not' in status_2:
				tkMessageBox.showwarning('Missing Events', '2 events are missing')
				pass
			elif 'Not' in status_1 or 'Not' in status_2:
				tkMessageBox.showwarning('Missing Events', '1 events is missing')
				pass
		elif self.get_num_event() == 3:
			if 'Not' in status_1 and 'Not' in status_2:
				tkMessageBox.showwarning('Missing Events', '3 events are missing')
				pass
			elif 'Not' in status_1:
				tkMessageBox.showwarning('Missing Operator', '1 operator is missing')
				pass
			elif 'Not' in status_2:
				tkMessageBox.showwarning('Missing Event', '1 event is missing')
				pass
		else:
			if 'Not' in status_1 and 'Not' in status_2:
				tkMessageBox.showwarning('Missing Operator', '2 operators are missing')
				pass
			elif 'Not' in status_1 or 'Not' in status_2:
				tkMessageBox.showwarning('Missing Operator', '1 operator is missing')
				pass

		if (len(description) == 0):
			choice = tkMessageBox.askyesno('Description', 'You do not have any description for this rule \n Are you sure ?')
			if choice == 0:
				return
			if choice == 1:
				pass

		self.set_max_delay(max_delay)
		self.set_min_delay(min_delay)
		self.set_description(description)

		title = 'Save As'
		file_type = [('XML', '.xml')]
		file_path = tkFileDialog.asksaveasfilename(filetypes=file_type, title=title,
													defaultextension='.xml')
		if not file_path:
			return
		else:
			self.write_to_file(file_path)
			if len(self.embedded_functions) > 0:
				tkMessageBox.showinfo('Embedded Function', 'You have declared some embedded functions in the rule \n'
															+ 'Please open the created rule to complete them')
			self.root.destroy()

	def write_to_file(self, file_path):
		content = self.to_string()
		file_path = file_path.split('/')
		file_path[-1] = self.get_id() + '.' + file_path[-1]
		file_path = '/'.join(file_path)

		file = open(file_path, 'wb')
		file.write(content)
		file.close()

	#-----------------End Main Window-----------------#

	#-----------------Operator Window-----------------#
	def init_operator_window(self, status_label, operator_id):
		operator_window = Tkinter.Toplevel()
		operator_window.transient(self.root)
		operator_window.title('Operator')
		operator = Operator(operator_window, operator_id)
		
		Tkinter.Label(operator_window, text='Value:').grid(row=0, column=0, sticky='w')
		value_menu = Tkinter.OptionMenu(operator_window, operator.value, *RULE_OPERATOR_VALUES)
		value_menu.config(width=5)
		value_menu.grid(row=0, column=1, padx=2, pady=2, sticky='w')

		Tkinter.Label(operator_window, text='Delay unit:').grid(row=1, column=0, sticky='w', padx=2, pady=2)
		unit_menu = Tkinter.OptionMenu(operator_window, operator.delay_unit, *UNITS)
		unit_menu.config(width=1)
		unit_menu.grid(row=1, column=1, padx=2, pady=2, sticky='w')

		Tkinter.Label(operator_window, text='Minimum delay:').grid(row=2, column=0, sticky='w', padx=2, pady=2)
		minimum_delay_text = Tkinter.Text(operator_window, height=1, width=8)
		minimum_delay_text.insert('insert', '0')
		minimum_delay_text.grid(row=2, column=1, padx=2, pady=2, sticky='w')
		minimum_delay_text.bind('<Tab>', self.focus_next_entry)

		Tkinter.Label(operator_window, text='Maximum delay:').grid(row=3, column=0, sticky='w', padx=2, pady=2)
		maximum_delay_text = Tkinter.Text(operator_window, height=1, width=8)
		maximum_delay_text.insert('insert', '0')
		maximum_delay_text.grid(row=3, column=1, padx=2, pady=2, sticky='w')
		maximum_delay_text.bind('<Tab>', self.focus_next_entry)


		Tkinter.Label(operator_window, text='Event 1:').grid(row=4, column=0, sticky='w', padx=2, pady=2)
		status_label_1 = Tkinter.Label(operator_window, text='          Not Available                ')
		status_label_1.grid(row=4, column=1)
		create_button_1 = Tkinter.Button(operator_window, text='Add Event')
		create_button_1.grid(row=4, column=2, sticky='e')

		Tkinter.Label(operator_window, text='Event 2:').grid(row=5, column=0, sticky='w', padx=2, pady=2)
		status_label_2 = Tkinter.Label(operator_window, text='          Not Available                ')
		status_label_2.grid(row=5, column=1)
		create_button_2 = Tkinter.Button(operator_window, text='Add Event')
		create_button_2.grid(row=5, column=2, sticky='e')

		if operator_id == 1:
			create_button_1.config(command=lambda: self.init_event_window(status_label_1, 1, operator_window, operator))
			create_button_2.config(command=lambda: self.init_event_window(status_label_2, 2, operator_window, operator))
		else: 
			create_button_1.config(command=lambda: self.init_event_window(status_label_1, 3, operator_window, operator))
			create_button_2.config(command=lambda: self.init_event_window(status_label_2, 4, operator_window, operator))

		add_button = Tkinter.Button(operator_window, text='Add Operator', command=lambda: self.add_operator(operator_window, operator, status_label)).grid(row=9, column=2, stick='e')

	def add_operator(self, operator_window, operator, status_label):
		maximum_delay = operator_window.grid_slaves(2, 1)[0].get('1.0', 'end-1c')
		minimum_delay = operator_window.grid_slaves(3, 1)[0].get('1.0', 'end-1c')

		#max = 0
		#min = 0
		if len(maximum_delay) == 0:
			tkMessageBox.showwarning('Empty Field', 'The maximum delay field cannot be empty')
			return
		#else:
			#try:
			#	max = float(maximum_delay)
			#except ValueError:
			#	tkMessageBox.showwarning('Invalid Value', 'The maximum delay must be a number')
			#	return

		if len(minimum_delay) == 0:
			tkMessageBox.showwarning('Empty Field', 'The minimum delay field cannot be empty')
			return
		#else:
			#try:
		#		min = float(minimum_delay)
			#except ValueError:
		#		tkMessageBox.showwarning('Invalid Value', 'The minimum delay must be a number')
		#		return

		#if max < min:
		#	tkMessageBox.showwarning('Invalid Value', 'The minimum delay must be smaller than the maximum delay')
		#	return

		operator.set_max_delay(maximum_delay)
		operator.set_min_delay(minimum_delay)

		status_1 = operator_window.grid_slaves(4, 1)[0]['text']
		status_2 = operator_window.grid_slaves(5, 1)[0]['text']

		if 'Not' in status_1 and 'Not' in status_2:
			tkMessageBox.showwarning('Missing Events', '2 events are missing')
			pass
		elif 'Not' in status_1 or 'Not' in status_2:
			tkMessageBox.showwarning('Missing Events', '1 events is missing')
			pass

		status_label['text'] = 'Created'

		self.add_created_operator(operator)
		operator_window.destroy()

	

	#-----------------End Operator Window-----------------#

	#-----------------Event Window-----------------#
	def init_event_window(self, status_label, event_id, parent=None,operator=None):
		event_window = Tkinter.Toplevel()
		event_window.title('Event')
		event_window.transient(parent)
		event = Event(event_window)

		Tkinter.Label(event_window, text='ID: ').grid(row=0, column=0, padx=2, pady=2, sticky='w')
		Tkinter.Label(event_window, text=event_id).grid(row=0, column=1, padx=2, pady=2, sticky='w')
		event.id = event_id

		Tkinter.Label(event_window, text='Value:').grid(row=1, column=0, sticky='w')
		event.value.set('COMPUTE')
		value_menu = Tkinter.OptionMenu(event_window, event.value, *EVENT_VALUES)
		value_menu.config(width=6)
		value_menu.grid(row=1, column=1, sticky='w')

		Tkinter.Label(event_window, text='Description:').grid(row=2, column=0, sticky='wn', padx=2, pady=2)
		description_text = Tkinter.Text(event_window, height=3, width=40)
		description_text.grid(row=2, column=1, sticky='we')
		description_text.insert('end', 'Desbribe your event')

		Tkinter.Label(event_window, text='Boolean Expression:').grid(row=5, column=0, sticky='wn', padx=2, pady=2)
		total_expression_text = Tkinter.Text(event_window, height=3, width=40)
		total_expression_text.config(state='disable')
		total_expression_text.grid(row=5, column=1)

		Tkinter.Button(event_window, text='Create Expression', command=lambda: self.add_expression(total_expression_text, event)).grid(row=8, column=1, sticky='w', padx=2, pady=2)
		Tkinter.Button(event_window, text='Add Event', command=lambda: self.add_event(event_window, event, status_label, operator)).grid(row=10, column=1, sticky='e', padx=2, pady=2)

	def add_expression(self, total_expression_text, event):
		choice = tkMessageBox.askyesno('New Expression', 'Embedded function is needed or not ?')
		if choice == 0:
			self.init_normal_expression_window(total_expression_text, event)
		if choice == 1:
			self.init_embedded_expression_window(total_expression_text, event)

	def add_event(self, event_window, event, status_label, operator):
		description = event_window.grid_slaves(2, 1)[0].get('1.0', 'end-1c')
		boolean_expression = event_window.grid_slaves(5, 1)[0].get('1.0', 'end-1c')

		if (len(boolean_expression) == 0):
			choice = tkMessageBox.askyesno('Boolean expression', 'Empty boolean expression\n Are you sure?')
                        if choice == 0:
                                return
                        if choice == 1:
                                pass

		if (len(description) == 0):
			choice = tkMessageBox.askyesno('Description', 'You do not have any description for this event \n Are you sure ?')
			if choice == 0:
				return
			if choice == 1:
				pass

		event.set_description(description)
		event.set_boolean_expression(boolean_expression)

		self.add_created_event(event)
		if operator != None:
			operator.add_created_event(event)
			status_label['text'] = '             Created                   '
		else:
			status_label['text'] = 'Created'

		event_window.destroy()

	#-----------------End Event Window-----------------#

	#-----------------Boolean Expression Window-----------------#
	def init_normal_expression_window(self, total_expression_text, event):
		expression_window = Tkinter.Toplevel()
		expression_window.title('Boolean Expression')
		expression_window.transient(event.window)
		expression = Expression(expression_window)
		expression.set_type('Normal')
		boolean_expression = ''
		hasRelation = 0

		if total_expression_text.get('1.0', 'end-1c') != '':
			hasRelation = 1
			relation = Tkinter.StringVar()
			relation.set(RELATIONS[0])
			Tkinter.Label(expression_window, text='Relation').grid(row=0, column=2, padx=2, pady=2, sticky='w')
			relation_menu = Tkinter.OptionMenu(expression_window, relation, *RELATIONS)
			relation_menu.config(width=2)
			relation_menu.grid(row=0, column=3, padx=2, pady=2, sticky='w')

		Tkinter.Label(expression_window, text='Type:').grid(row=1, column=2, padx=2, pady=2, sticky='w')
		Tkinter.Label(expression_window, text='Normal').grid(row=1, column=3, padx=2, pady=2, sticky='w')

		list_protocols = self.protos.keys()
		list_protocols.sort()

		scrollbar = Tkinter.Scrollbar(expression_window)
		scrollbar.grid(row=0, column=1, sticky='nsw', rowspan=5)

		Tkinter.Label(expression_window, text='Attribute:').grid(row=3, column=2, padx=2, pady=2, sticky='w')
		attr_menu = ttk.Combobox(expression_window, textvariable=expression.attribute)
		attr_menu.config(width=8)
		attr_menu.grid(row=3, column=3, padx=2, pady=2, sticky='w')

		Tkinter.Label(expression_window, text='Protocol:').grid(row=2, column=2, padx=2, pady=2, sticky='w')
		protocol_entry = Tkinter.Entry(expression_window, width=10)
		protocol_entry.grid(row=2, column=3, padx=2, pady=2, sticky='w')

		protocol_list_box = Tkinter.Listbox(expression_window, yscrollcommand=scrollbar.set, selectmode='single', height=10)
		protocol_list_box.grid(row=0, column=0, rowspan=5)
		protocol_list_box.bind('<<ListboxSelect>>', lambda _: self.choose_protocol(protocol_list_box, 
																					protocol_entry,
																					attr_menu,
																					expression.attribute))
		for i in list_protocols:
			protocol_list_box.insert('end', i)
		scrollbar.config(command=protocol_list_box.yview)

		protocol = Tkinter.StringVar()
		protocol.trace('w', lambda name, index, mode, 
									var=protocol, 
									list_protocols=list_protocols, 
									list_box=protocol_list_box:self.search_protocol(var, list_protocols, list_box))
		protocol_entry.config(textvariable=protocol)

		Tkinter.Label(expression_window, text='        ').grid(row=3, column=4, padx=2, pady=2)

		Tkinter.Label(expression_window, text='Comparison:').grid(row=3, column=5, padx=2, pady=2)
		comparison_menu = Tkinter.OptionMenu(expression_window, expression.comparison, *COMPARISONS)
		comparison_menu.config(width=1, height=1)
		comparison_menu.grid(row=3, column=6)

		Tkinter.Label(expression_window, text='        ').grid(row=3, column=7, padx=2, pady=2)

		search_pointer_button = Tkinter.Button(expression_window, text='Search')

		Tkinter.Label(expression_window, text='Value Type:').grid(row=3, column=8, padx=2, pady=2)
		value_type = Tkinter.StringVar()
		attr_value_type = Tkinter.OptionMenu(expression_window, value_type, *VALUE_TYPES, command=lambda _: self.init_value_type(value_type.get(), attr_value_text, search_pointer_button))
		attr_value_type.config(width=10)
		attr_value_type.grid(row=3, column=9, padx=2, pady=2, sticky='w')

		Tkinter.Label(expression_window, text='        ').grid(row=3, column=10, padx=2, pady=2)

		Tkinter.Label(expression_window, text='Value:').grid(row=3, column=11, padx=2, pady=2)
		attr_value_text = Tkinter.Text(expression_window, height=1, width=10)
		attr_value_text.grid(row=3, column=12, padx=2, pady=2, sticky='w')
		search_pointer_button.config(command=lambda: self.init_pointer_window(attr_value_text, expression_window))

		create_button = Tkinter.Button(expression_window, text='Add Expression')
		create_button.grid(row=4, column=7, columnspan=3, sticky='e')
		if hasRelation == 1:
			create_button.config(command=lambda: self.create_expression(event, 
																		expression,  
																		total_expression_text, 
																		expression_window, 
																		relation.get()))
		else:
			create_button.config(command=lambda: self.create_expression(event, 
																		expression,
																		total_expression_text, 
																		expression_window))

	def init_value_type(self, value_type, attr_value_text, search_pointer_button):
		attr_value_text.delete('1.0', 'end')
		search_pointer_button.grid_forget()
		if value_type == 'proto.attribute':
			search_pointer_button.grid(row=3, column=13, padx=2, pady=2, sticky='w')

	def init_pointer_window(self, pointer_value_text, parent):
		pointer_window = Tkinter.Toplevel()
		pointer_window.transient(parent)

		list_protocols = self.protos.keys()
		list_protocols.sort()

		scrollbar = Tkinter.Scrollbar(pointer_window)
		scrollbar.grid(row=0, column=1, sticky='nsw', rowspan=5)

		Tkinter.Label(pointer_window, text='Attribute:').grid(row=0, column=5, padx=2, pady=2, sticky='w')
		attr = Tkinter.StringVar()
		attr_menu = ttk.Combobox(pointer_window, textvariable=attr)
		attr_menu.config(width=8)
		attr_menu.grid(row=0, column=6, padx=2, pady=2, sticky='w')

		Tkinter.Label(pointer_window, text='Protocol:').grid(row=0, column=2, padx=2, pady=2, sticky='w')
		protocol_entry = Tkinter.Entry(pointer_window, width=10)
		protocol_entry.grid(row=0, column=3, padx=2, pady=2, sticky='w')

		Tkinter.Label(pointer_window, text='          ').grid(row=0, column=4, padx=2, pady=2, sticky='w')

		protocol_list_box = Tkinter.Listbox(pointer_window, yscrollcommand=scrollbar.set, selectmode='single', height=10)
		protocol_list_box.grid(row=0, column=0, rowspan=5)
		protocol_list_box.bind('<<ListboxSelect>>', lambda _: self.choose_protocol(protocol_list_box, 
																					protocol_entry,
																					attr_menu,
																					attr))
		add_pointer_button = Tkinter.Button(pointer_window, text='Add Pointer')
		add_pointer_button.grid(column=5, row=5, columnspan=2, padx=2, pady=2, sticky='e')

		for i in list_protocols:
			protocol_list_box.insert('end', i)
		scrollbar.config(command=protocol_list_box.yview)

		protocol = Tkinter.StringVar()
		protocol.trace('w', lambda name, index, mode, 
									var=protocol, 
									list_protocols=list_protocols, 
									list_box=protocol_list_box:self.search_protocol(var, list_protocols, list_box))

		add_pointer_button.config(command=lambda: self.add_pointer(protocol, attr, pointer_value_text, pointer_window))

		protocol_entry.config(textvariable=protocol)


	def init_embedded_expression_window(self, total_expression_text, event):
		expression_window = Tkinter.Toplevel()
		expression_window.title('Boolean Expression')
		expression_window.transient(event.window)
		expression = Expression(expression_window)
		expression.set_type('Embedded Function')
		boolean_expression = ''
		hasRelation = 0

		if total_expression_text.get('1.0', 'end-1c') != '':
			hasRelation = 1
			relation = Tkinter.StringVar()
			relation.set(RELATIONS[0])
			Tkinter.Label(expression_window, text='Relation').grid(row=0, column=0, padx=2, pady=2, sticky='w')
			relation_menu = Tkinter.OptionMenu(expression_window, relation, *RELATIONS)
			relation_menu.config(width=2)
			relation_menu.grid(row=0, column=1, padx=2, pady=2, sticky='w')

		Tkinter.Label(expression_window, text='Type:').grid(row=1, column=0, padx=2, pady=2, sticky='w')
		Tkinter.Label(expression_window, text='Embedded Function').grid(row=1, column=1, padx=2, pady=2, sticky='w')

		Tkinter.Label(expression_window, text='Function name:').grid(row=2, column=0, padx=2, pady=2, sticky='w')
		name_text = Tkinter.Text(expression_window)
		name_text.config(height=1, width=20)
		name_text.grid(row=2, column=1, sticky='w')

		Tkinter.Label(expression_window, text='Number of argument:').grid(row=3, column=0, padx=2, pady=2)
		num_arg_menu = Tkinter.OptionMenu(expression_window, expression.num_argument, *[0, 1, 2, 3, 4, 5, 6, 7],
											command=lambda _: self.show_arg(expression_window, sub_frames, expression.num_argument))
		num_arg_menu.config(width=2)
		num_arg_menu.grid(row=3, column=1, sticky='w')

		Tkinter.Label(expression_window, text='Comparison:').grid(row=3, column=3, padx=2, pady=2)
		comparison_menu = Tkinter.OptionMenu(expression_window, expression.comparison, *COMPARISONS)
		comparison_menu.config(width=1, height=1)
		comparison_menu.grid(row=3, column=4)

		Tkinter.Label(expression_window, text='        ').grid(row=3, column=5, padx=2, pady=2)

		Tkinter.Label(expression_window, text='Value:').grid(row=3, column=6, padx=2, pady=2)
		attr_value_text = Tkinter.Text(expression_window)
		attr_value_text.config(height=1, width=5)
		attr_value_text.grid(row=3, column=7, sticky='w')

		sub_frames = []
		arg_frame = Tkinter.Frame(expression_window)
		arg_frame.grid(row=4, column=0, columnspan=8, padx=2, pady=2)

		for i in range(7):
			new_frame = Tkinter.Frame(arg_frame)
			new_frame.grid(row=i, column=0, padx=2, pady=2, sticky='w')
			Tkinter.Label(new_frame, text='Argument ' + str(i + 1) +':').grid(row=0, column=0, padx=2, pady=2, sticky='w')
			pointer_value_text = Tkinter.Text(new_frame, height=1, width=20)
			pointer_value_text.grid(row=0, column=1, padx=2, pady=2, sticky='w')
			search_pointer_button = Tkinter.Button(new_frame, text='Search')
			search_pointer_button.grid(row=0, column=2, padx=2, pady=2, sticky='w')
			sub_frames.append(new_frame)
			new_frame.grid_forget()

		create_button = Tkinter.Button(expression_window, text='Add Expression')
		create_button.grid(row=5, column=5, columnspan=3, sticky='e')
		if hasRelation == 1:
			create_button.config(command=lambda: self.create_expression(event, 
																		expression,  
																		total_expression_text, 
																		expression_window, 
																		relation.get()))
		else:
			create_button.config(command=lambda: self.create_expression(event, 
																		expression,  
																		total_expression_text, 
																		expression_window))

	def show_arg(self, window, list_frame, num_arg):
		num = num_arg.get()

		for i in list_frame:
			i.grid_forget()
		
		if num == 0:
			return

		for i in range(num):
			list_frame[i].grid(row=i, column=0, padx=2, pady=2, sticky='w')
			text = list_frame[i].grid_slaves(0, 1)[0]
			button = list_frame[i].grid_slaves(0, 2)[0]
			button.config(command=lambda text=text: self.init_pointer_window(text, window))


	def search_protocol(self, var, list_protocols, list_box):
		search_field = var.get()
		result = []
		for i in list_protocols:
			if search_field in i:
				result.append(i)

		list_box.delete('0', 'end')
		for i in result:
			list_box.insert('end', i)


	def choose_protocol(self, list_box, protocol_entry, attr_menu, attr_var):
		chosen_protocol = list_box.get(list_box.curselection())
		protocol_entry.delete('0', 'end')
		protocol_entry.insert('end', chosen_protocol)

		attr_list = self.protos[chosen_protocol]
		attr_menu['values'] = attr_list

	def add_pointer(self, proto, attr, pointer_value_text, pointer_window):
		protocol = proto.get()
		attribute = attr.get()

		if len(protocol) == 0: 
			tkMessageBox.showwarning('Empty Field', 'The protocol field cannot be empty')
			return

		if len(attribute) == 0: 
			tkMessageBox.showwarning('Empty Field', 'The attribute field cannot be empty')
			return

		pointer_value_text.delete('1.0', 'end')
		pointer_value_text.insert('end', protocol + '.' + attribute)

		pointer_window.destroy()

	def create_expression(self, event, expression, total_expression_text, window, rel=None):
		total_expression_text.config(state='normal')
		value = ''
		args = []

		if (expression.get_type() == 'Normal'):
			value_text = window.grid_slaves(3, 12)[0]
			value = value_text.get('1.0', 'end-1c')

			protocol_entry = window.grid_slaves(2, 3)[0]
			protocol = protocol_entry.get()

			expression.set_protocol(protocol)
			# Field validation 
			if len(expression.get_protocol()) == 0:
				tkMessageBox.showwarning('Empty Field', 'The protocol field cannot be empty')
				return
			if len(expression.get_attribute()) == 0:
				tkMessageBox.showwarning('Empty Field', 'The attribute field cannot be empty')
				return
			
			if len(value) == 0:
				tkMessageBox.showwarning('Empty Field', 'The value field cannot be empty')
				return

		else:
			function_name = window.grid_slaves(2, 1)[0].get('1.0', 'end-1c')
			
			for i in range(expression.get_num_argument()):
				args.append(window.grid_slaves(4,0)[0].grid_slaves(i,0)[0].grid_slaves(0,1)[0].get('1.0', 'end-1c'))

			value_text = window.grid_slaves(3, 7)[0]
			value = value_text.get('1.0', 'end-1c')

			expression.set_function_name(function_name)

			# Field validation 
			if len(expression.get_function_name()) == 0:
				tkMessageBox.showwarning('Empty Field', 'The function name cannot be empty')
				return
			for i in range(expression.get_num_argument()):
				if len(args[i]) == 0:
					tkMessageBox.showwarning('Empty Field', 'Argument ' + str(i + 1) +' cannot be empty')
					return

			if len(value) == 0:
				tkMessageBox.showwarning('Empty Field', 'The value field cannot be empty')
				return

			self.embedded_functions.append(function_name)

		if expression.get_comparison() == '>':
			expression.set_comparison('&gt;')
		elif expression.get_comparison() == '<':
			expression.set_comparison('&lt;')
		expression.set_value(value)

		expr = ''
		if expression.get_type() == 'Normal':
			expr = expression.get_protocol() + '.' + expression.get_attribute() 
		else:
			expr = '#' + expression.get_function_name() + '('
			if expression.get_num_argument() == 0:
				expr += ')'
			else:
				expr += args[0]
				for i in range(1, expression.get_num_argument()):
					expr += ', ' + args[1]
				expr += ')'

		expr += ' ' + expression.get_comparison() + ' ' + expression.get_value()
					

		event.make_expression(expr, rel)
		total_expression_text.delete('1.0', 'end')
		total_expression_text.insert('end', event.boolean_expression)
		total_expression_text.config(state='disable')
		window.destroy()


	#-----------------End Boolean Expression Window-----------------#
if __name__ == '__main__':	
	root = Tkinter.Tk()
	Rule(root)
	root.mainloop()
