import sqlite3
from datetime import datetime, timedelta, timezone
import os

class Database:
    def __init__(self, db_path='analysis.db'):
        """初始化数据库"""
        try:
            self.db_path = db_path
            self.init_database()
        except Exception as e:
            print(f"初始化数据库时出错: {str(e)}")
            raise

    def init_database(self):
        """初始化数据库表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 创建分析记录表
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    request_count INTEGER DEFAULT 0
                )
                ''')
                
                # 创建网络请求表
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    domain TEXT,
                    ip TEXT,
                    port TEXT,
                    timestamp TEXT,
                    country TEXT,
                    region TEXT,
                    city TEXT,
                    isp TEXT,
                    org TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_records(id)
                )
                ''')
                
                conn.commit()
                print("数据库初始化成功")
                
        except Exception as e:
            print(f"创建数据库表时出错: {str(e)}")
            raise

    def to_china_timezone(self, dt):
        """转换时间到中国时区"""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        china_tz = timezone(timedelta(hours=8))  # 中国时区 UTC+8
        return dt.astimezone(china_tz)

    def save_results(self, results):
        """保存分析结果到数据库"""
        try:
            print("开始保存分析结果到数据库...")
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 获取当前中国时间
                current_time = datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
                
                # 检查是否已存在相同文件名的记录
                cursor.execute('''
                SELECT id FROM analysis_records 
                WHERE filename = ?
                ''', (results['file_name'],))
                
                existing_record = cursor.fetchone()
                
                if existing_record:
                    analysis_id = existing_record[0]
                    print(f"找到已存在的分析记录，ID: {analysis_id}")
                    
                    # 更新分析记录
                    cursor.execute('''
                    UPDATE analysis_records 
                    SET file_hash = ?,
                        analysis_time = ?,
                        request_count = ?
                    WHERE id = ?
                    ''', (
                        results['hash'],
                        current_time,
                        len(results.get('requests', [])),
                        analysis_id
                    ))
                    
                    # 删除旧的请求数据
                    cursor.execute('''
                    DELETE FROM network_requests 
                    WHERE analysis_id = ?
                    ''', (analysis_id,))
                    
                    print("已更新分析记录并删除旧的请求数据")
                    
                else:
                    # 保存新的分析记录
                    cursor.execute('''
                    INSERT INTO analysis_records (filename, file_hash, analysis_time, request_count)
                    VALUES (?, ?, ?, ?)
                    ''', (
                        results['file_name'],
                        results['hash'],
                        current_time,
                        len(results.get('requests', []))
                    ))
                    
                    analysis_id = cursor.lastrowid
                    print(f"已创建新的分析记录，ID: {analysis_id}")
                
                # 保存网络请求数据，同时去重
                seen_requests = set()  # 用于记录已处理的请求
                request_count = 0
                
                for request in results.get('requests', []):
                    try:
                        # 生成请求的唯一标识
                        request_key = f"{request.get('domain', '')}-{request.get('ip', '')}"
                        
                        # 如果是重复的请求，跳过
                        if request_key in seen_requests:
                            continue
                            
                        seen_requests.add(request_key)
                        
                        # 处理时间戳
                        try:
                            timestamp_str = request.get('timestamp', '')
                            if isinstance(timestamp_str, str):
                                if 'Z' in timestamp_str:  # ISO格式
                                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                    timestamp = self.to_china_timezone(timestamp)
                                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                                elif timestamp_str.isdigit():  # Unix时间戳
                                    timestamp = datetime.fromtimestamp(int(timestamp_str)/1000, timezone.utc)
                                    timestamp = self.to_china_timezone(timestamp)
                                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                            elif isinstance(timestamp_str, (int, float)):  # 数字类型时间戳
                                timestamp = datetime.fromtimestamp(timestamp_str/1000, timezone.utc)
                                timestamp = self.to_china_timezone(timestamp)
                                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            timestamp_str = current_time
                        
                        cursor.execute('''
                        INSERT INTO network_requests (
                            analysis_id, domain, ip, port, timestamp,
                            country, region, city, isp, org
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            analysis_id,
                            request.get('domain', ''),
                            request.get('ip', ''),
                            request.get('port', ''),
                            timestamp_str,
                            request.get('country', ''),
                            request.get('region', ''),
                            request.get('city', ''),
                            request.get('isp', ''),
                            request.get('org', '')
                        ))
                        request_count += 1
                    except Exception as e:
                        print(f"保存请求数据时出错: {str(e)}")
                        print(f"请求数据: {request}")
                        continue
                
                # 更新请求数量
                cursor.execute('''
                UPDATE analysis_records 
                SET request_count = ? 
                WHERE id = ?
                ''', (request_count, analysis_id))
                
                conn.commit()
                print(f"成功保存分析结果，共 {request_count} 条请求记录")
                
        except Exception as e:
            print(f"保存分析结果到数据库时出错: {str(e)}")
            print(f"结果数据: {results}")
            raise

    def get_analysis_list(self):
        """获取分析记录列表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                SELECT id, filename, file_hash, analysis_time, request_count
                FROM analysis_records
                ORDER BY analysis_time DESC
                ''')
                return cursor.fetchall()
        except Exception as e:
            print(f"获取分析记录列表时出错: {str(e)}")
            return []

    def get_requests_by_analysis(self, analysis_id):
        """获取指定分析记录的网络请求数据"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 设置文本工厂以正确处理编码
                conn.text_factory = str
                cursor = conn.cursor()
                
                # 获取所有请求数据
                cursor.execute('''
                SELECT domain, ip, port, timestamp, country, region, city, isp, org
                FROM network_requests
                WHERE analysis_id = ?
                ''', (analysis_id,))
                
                results = cursor.fetchall()
                
                # 处理时间戳为中国时区并确保编码正确
                formatted_results = []
                for row in results:
                    try:
                        # 转换每个字段确保编码正确
                        formatted_row = []
                        for item in row:
                            if isinstance(item, bytes):
                                try:
                                    item = item.decode('utf-8')
                                except:
                                    item = str(item)
                            formatted_row.append(item)
                        
                        # 转换时间戳到中国时区
                        timestamp_str = formatted_row[3]  # timestamp 在第4列
                        if timestamp_str:
                            try:
                                # 尝试解析不同格式的时间字符串
                                dt = None
                                if 'T' in timestamp_str:  # ISO格式
                                    if '+' in timestamp_str:
                                        dt = datetime.fromisoformat(timestamp_str)
                                    else:
                                        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                else:
                                    try:
                                        # 尝试标准格式
                                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                                    except:
                                        # 尝试带毫秒的格式
                                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                                
                                if dt:
                                    # 确保时区信息
                                    if dt.tzinfo is None:
                                        dt = dt.replace(tzinfo=timezone.utc)
                                    # 转换到中国时区
                                    china_tz = timezone(timedelta(hours=8))
                                    dt = dt.astimezone(china_tz)
                                    # 格式化为字符串
                                    formatted_row[3] = dt.strftime('%Y-%m-%d %H:%M:%S')
                            except Exception as e:
                                print(f"转换时间戳出错: {str(e)}, 原始时间戳: {timestamp_str}")
                        
                        formatted_results.append(tuple(formatted_row))
                        
                    except Exception as e:
                        print(f"处理请求数据行时出错: {str(e)}")
                        formatted_results.append(row)  # 如果处理出错，使用原始数据
                
                return formatted_results
                
        except Exception as e:
            print(f"获取网络请求数据时出错: {str(e)}")
            import traceback
            print(f"错误堆栈: {traceback.format_exc()}")
            return []

    def delete_record(self, filename, analysis_time):
        """删除数据库记录"""
        try:
            print(f"尝试删除记录 - 文件名: {filename}, 时间: {analysis_time}")
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 首先找到对应的分析记录ID
                cursor.execute('''
                SELECT id, filename, analysis_time 
                FROM analysis_records 
                WHERE filename LIKE ? 
                ''', (f"%{filename}%",))
                
                records = cursor.fetchall()
                print(f"找到 {len(records)} 条可能匹配的记录")
                
                # 找到最匹配的记录
                analysis_id = None
                for record in records:
                    rec_id, rec_filename, rec_time = record
                    print(f"检查记录 - ID: {rec_id}, 文件名: {rec_filename}, 时间: {rec_time}")
                    
                    # 转换时间格式以便比较
                    try:
                        db_time = datetime.strptime(rec_time, '%Y-%m-%d %H:%M:%S')
                        db_time = db_time.replace(tzinfo=timezone(timedelta(hours=8)))
                        
                        input_time = datetime.strptime(analysis_time, '%Y-%m-%d %H:%M:%S')
                        input_time = input_time.replace(tzinfo=timezone(timedelta(hours=8)))
                        
                        time_diff = abs((db_time - input_time).total_seconds())
                        
                        # 如果文件名包含且时间差在1分钟内
                        if filename in rec_filename and time_diff < 60:
                            analysis_id = rec_id
                            print(f"找到匹配记录 - ID: {analysis_id}")
                            break
                    except Exception as e:
                        print(f"比较时间时出错: {str(e)}")
                        continue
                
                if analysis_id:
                    print(f"开始删除记录 ID: {analysis_id}")
                    
                    # 删除相关的网络请求数据
                    cursor.execute('''
                    DELETE FROM network_requests 
                    WHERE analysis_id = ?
                    ''', (analysis_id,))
                    print(f"已删除网络请求数据")
                    
                    # 删除分析记录
                    cursor.execute('''
                    DELETE FROM analysis_records 
                    WHERE id = ?
                    ''', (analysis_id,))
                    print(f"已删除分析记录")
                    
                    conn.commit()
                    print("删除操作已提交")
                    return True
                else:
                    print(f"未找到匹配的记录")
                    return False
                
        except Exception as e:
            print(f"删除数据库记录时出错: {str(e)}")
            print(f"文件名: {filename}")
            print(f"时间: {analysis_time}")
            raise 

    def get_total_records(self, conditions=None):
        """获取总记录数"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = "SELECT COUNT(*) FROM analysis_records WHERE 1=1"
                params = []
                
                if conditions:
                    if 'filename' in conditions:
                        query += " AND filename LIKE ?"
                        params.append(f"%{conditions['filename']}%")
                    if 'date_from' in conditions:
                        query += " AND analysis_time >= ?"
                        params.append(conditions['date_from'])
                    if 'date_to' in conditions:
                        query += " AND analysis_time <= ?"
                        params.append(conditions['date_to'])
                
                cursor.execute(query, params)
                return cursor.fetchone()[0]
                
        except Exception as e:
            print(f"获取记录总数失败: {str(e)}")
            return 0

    def get_records_page(self, offset, limit, conditions=None):
        """获取分页数据"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 设置文本工厂以正确处理编码
                conn.text_factory = str
                cursor = conn.cursor()
                
                query = """
                    SELECT analysis_time, filename, request_count, file_hash
                    FROM analysis_records
                    WHERE 1=1
                """
                params = []
                
                if conditions:
                    if 'filename' in conditions:
                        query += " AND filename LIKE ?"
                        params.append(f"%{conditions['filename']}%")
                    if 'date_from' in conditions:
                        query += " AND analysis_time >= ?"
                        params.append(conditions['date_from'])
                    if 'date_to' in conditions:
                        query += " AND analysis_time <= ?"
                        params.append(conditions['date_to'])
                
                query += " ORDER BY analysis_time DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                results = cursor.fetchall()
                
                # 确保所有字符串都是 UTF-8 编码
                formatted_results = []
                for row in results:
                    formatted_row = []
                    for item in row:
                        if isinstance(item, bytes):
                            try:
                                item = item.decode('utf-8')
                            except:
                                item = str(item)
                        formatted_row.append(item)
                    formatted_results.append(tuple(formatted_row))
                
                return formatted_results
                
        except Exception as e:
            print(f"获取分页数据失败: {str(e)}")
            import traceback
            print(f"错误堆栈: {traceback.format_exc()}")
            return [] 